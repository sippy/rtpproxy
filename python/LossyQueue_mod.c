#include <stdbool.h>

#include <Python.h>
#include "SPMCQueue.h"

#define MODULE_BASENAME LossyQueue

#define CONCATENATE_DETAIL(x, y) x##y
#define CONCATENATE(x, y) CONCATENATE_DETAIL(x, y)

#if !defined(DEBUG_MOD)
#define MODULE_NAME MODULE_BASENAME
#else
#define MODULE_NAME CONCATENATE(MODULE_BASENAME, _debug)
#endif

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#define MODULE_NAME_STR TOSTRING(MODULE_NAME)
#define PY_INIT_FUNC CONCATENATE(PyInit_, MODULE_NAME)

typedef struct {
    PyObject_HEAD
    SPMCQueue* queue;
} PyLossyQueue;

static int PyLossyQueue_init(PyLossyQueue* self, PyObject* args, PyObject* kwds) {
    int size;
    static char *kwlist[] = {"size", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &size)) {
        return -1;
    }

    // Check if size is a power of two
    if (size <= 0 || (size & (size - 1)) != 0) {
        PyErr_SetString(PyExc_ValueError, "Queue size must be a power of two");
        return -1;
    }

    self->queue = create_queue(size);
    if(self->queue == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Error initializing queue");
        return -1;
    }

    return 0;
}

// The __del__ method for PyLossyQueue objects
static void PyLossyQueue_dealloc(PyLossyQueue* self) {
    PyObject* item;
    if (self->queue != NULL) {
        while (try_pop(self->queue, (void **)&item)) {
            Py_DECREF(item);
        }
        destroy_queue(self->queue);  // replace with actual queue destruction function
    }
    Py_TYPE(self)->tp_free((PyObject*)self);
}

// The put method for PyLossyQueue objects
static PyObject* PyLossyQueue_put(PyLossyQueue* self, PyObject* args) {
    PyObject* item;
    if (!PyArg_ParseTuple(args, "O", &item)) {
        return NULL;
    }

    Py_INCREF(item);
    while (!try_push(self->queue, item)) {
        PyObject* old_item;
        if (try_pop(self->queue, (void **)&old_item)) {
            Py_DECREF(old_item);
        }
    }

    Py_RETURN_NONE;
}

// The get method for PyLossyQueue objects
static PyObject* PyLossyQueue_get(PyLossyQueue* self) {
    PyObject* item;
    if (try_pop(self->queue, (void **)&item)) {
        //Py_DECREF(item);
        return item;
    }
    Py_RETURN_NONE;
}

static PyMethodDef PyLossyQueue_methods[] = {
    {"put", (PyCFunction)PyLossyQueue_put, METH_VARARGS, "Put an item into the queue"},
    {"get", (PyCFunction)PyLossyQueue_get, METH_NOARGS, "Get an item from the queue"},
    {NULL}  // Sentinel
};

static PyTypeObject PyLossyQueueType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = MODULE_NAME_STR "." MODULE_NAME_STR,
    .tp_doc = "Single producer multiple consumers queue",
    .tp_basicsize = sizeof(PyLossyQueue),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_init = (initproc)PyLossyQueue_init,
    .tp_dealloc = (destructor)PyLossyQueue_dealloc,
    .tp_methods = PyLossyQueue_methods,
};

static struct PyModuleDef LossyQueue_module = {
    PyModuleDef_HEAD_INIT,
    .m_name = MODULE_NAME_STR,
    .m_doc = "Python interface for a lock-free Single Producer Multiple Consumers (SPMC) queue.",
    .m_size = -1,
};

// Module initialization function
PyMODINIT_FUNC PY_INIT_FUNC(void) {
    PyObject* module;
    if (PyType_Ready(&PyLossyQueueType) < 0)
        return NULL;

    module = PyModule_Create(&LossyQueue_module);
    if (module == NULL)
        return NULL;

    Py_INCREF(&PyLossyQueueType);
    PyModule_AddObject(module, MODULE_NAME_STR, (PyObject*)&PyLossyQueueType);

    return module;
}

