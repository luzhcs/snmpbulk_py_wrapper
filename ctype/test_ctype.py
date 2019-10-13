import ctypes

lib = ctypes.cdll.LoadLibrary('../libsnmp_mon.dylib')

lib.main()
