#!/usr/bin/env python3
"""Bounded, read-only inspection of the pinned little-endian OSv ROFS v1."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

MAGIC = 0xDEADBEAD
MAX_TABLE_BYTES = 16*1024*1024
MAX_NODES = 100000


def inspect(image, include_directories=False):
    with image.open('rb') as stream:
        size = image.stat().st_size
        def read(offset,length):
            if offset < 0 or length < 0 or offset+length > size:
                raise ValueError('ROFS image range exceeds file')
            stream.seek(offset)
            result = stream.read(length)
            if len(result) != length:
                raise ValueError('short ROFS image read')
            return result
        header = read(0,min(size,512))
        candidates=[]
        if len(header) >= 64 and struct.unpack_from('<Q',header)[0] == MAGIC:
            candidates.append((0,size))
        elif len(header) == 512 and header[510:] == b'\x55\xaa':
            for index in range(4):
                _,_,kind,_,start,sectors = struct.unpack_from('<B3sB3sII',header,446+16*index)
                if kind and sectors:
                    base,length = start*512,sectors*512
                    if not start or base+length > size:
                        raise ValueError('MBR partition exceeds image')
                    if length >= 64 and struct.unpack('<Q',read(base,8))[0] == MAGIC:
                        candidates.append((base,length))
        if len(candidates) != 1:
            raise ValueError('requires exactly one ROFS partition')
        base,length = candidates[0]
        magic,version,block,first,blocks,ndirs,nlinks,nodes = struct.unpack('<8Q',read(base,64))
        if (magic != MAGIC or version != 1 or block != 512 or not first or not blocks or
                blocks*512 > MAX_TABLE_BYTES or (first+blocks)*512 > length or
                not 1 <= nodes <= MAX_NODES or ndirs != nodes-1 or nlinks > nodes):
            raise ValueError('unsupported or unbounded ROFS header')
        table = read(base+first*512,blocks*512)
        cursor=0
        def take(count):
            nonlocal cursor
            if count < 0 or cursor+count > len(table):
                raise ValueError('ROFS table exceeds metadata range')
            result = table[cursor:cursor+count]
            cursor += count
            return result
        def text():
            count, = struct.unpack('<H',take(2))
            if not 1 <= count <= 4096:
                raise ValueError('invalid ROFS string length')
            value = take(count).decode('utf-8')
            if '\x00' in value:
                raise ValueError('NUL in ROFS string')
            return value
        entries=[]
        for _ in range(ndirs):
            number, = struct.unpack('<Q',take(8))
            name = text()
            if name in ('.','..') or '/' in name or '\\' in name:
                raise ValueError('noncanonical ROFS directory entry')
            entries.append((number,name))
        links=[text() for _ in range(nlinks)]
        inodes=[struct.unpack('<4Q',take(32)) for _ in range(nodes)]
        if any(number != index+1 for index,(_,number,_,_) in enumerate(inodes)):
            raise ValueError('invalid ROFS inode numbers')
        if inodes[0][0]&0xf000 != 0x4000:
            raise ValueError('ROFS root is not a directory')
        visited,used_entries,used_links=set(),set(),set()
        pending=[(1,'',0)]
        files={}
        directories=[]
        while pending:
            number,parent,depth=pending.pop()
            if not 1 <= number <= nodes or number in visited or depth > 256:
                raise ValueError('ROFS cycle, duplicate inode or excessive depth')
            visited.add(number)
            mode,_,offset,count=inodes[number-1]
            kind=mode&0xf000
            if kind == 0x4000:
                if include_directories:
                    directories.append({'path':parent or '/', 'mode':mode, 'children':count})
                if offset+count > len(entries):
                    raise ValueError('directory exceeds entry table')
                names=set()
                for index in range(offset,offset+count):
                    child,name=entries[index]
                    if index in used_entries or name in names:
                        raise ValueError('overlapping or duplicate directory entry')
                    used_entries.add(index)
                    names.add(name)
                    pending.append((child,parent+'/'+name,depth+1))
            elif kind == 0xa000:
                if count != 1 or offset >= len(links) or offset in used_links:
                    raise ValueError('invalid ROFS symbolic link')
                used_links.add(offset)
                files[parent]={'path':parent,'symlink':links[offset]}
            elif kind == 0x8000:
                if offset < 1 or offset*512+count > first*512:
                    raise ValueError('file overlaps ROFS metadata or header')
                digest=hashlib.sha256()
                remaining=count
                position=base+offset*512
                while remaining:
                    step=min(1048576,remaining)
                    digest.update(read(position,step))
                    position+=step
                    remaining-=step
                files[parent]={'path':parent,'size':count,'sha256':digest.hexdigest()}
            else:
                raise ValueError('unsupported ROFS inode type')
        if len(visited) != nodes or len(used_entries) != ndirs or len(used_links) != nlinks:
            raise ValueError('unreachable ROFS metadata')
        result = {'protocol':'osv-rofs-inspection/v1','partition_offset':base,'partition_size':length,
            'files':sorted(files.values(),key=lambda item:item['path'])}
        if include_directories:
            result['directories'] = sorted(directories,key=lambda item:item['path'])
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        raise ValueError('requires a fresh inspection output')
    result=inspect(args.image)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print('ROFS inspected files: '+str(len(result['files'])),flush=True)


if __name__ == '__main__':
    main()
