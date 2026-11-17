/* SPDX-License-Identifier: BSD-3-Clause */
/* One isolated interpreter per one-use VM; argv is the OSJ1 payload, never a shell. */
#include <Python.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (setenv("OPENBLAS_NUM_THREADS", "1", 1) || setenv("OMP_NUM_THREADS", "1", 1))
        return 125;
    /* Guest argv and JSON are UTF-8, independent of the boot locale. */
    PyPreConfig preconfig;
    PyPreConfig_InitIsolatedConfig(&preconfig);
    preconfig.utf8_mode = 1;
    PyStatus status = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(status))
        Py_ExitStatusException(status);
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    /* IsolatedConfig defaults to parse_argv=0, which would ignore -c/-m/-V. */
    config.parse_argv = 1;
    config.write_bytecode = 0;
    status = PyConfig_SetBytesString(&config, &config.home, "/opt/python");
    if (!PyStatus_Exception(status))
        status = PyConfig_SetBytesArgv(&config, argc, argv);
    if (!PyStatus_Exception(status))
        status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        if (PyStatus_IsExit(status))
            return status.exitcode;
        Py_ExitStatusException(status);
    }
    return Py_RunMain();
}
