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
    size_t queue_size;
    PyObject** push_buffer;
    PyObject** pop_buffer;
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
    self->queue_size = (size_t)size;
    self->push_buffer = PyMem_New(PyObject*, self->queue_size);
    self->pop_buffer = PyMem_New(PyObject*, self->queue_size);
    if (self->push_buffer == NULL || self->pop_buffer == NULL) {
        destroy_queue(self->queue);
        self->queue = NULL;
        self->queue_size = 0;
        PyMem_Free(self->push_buffer);
        PyMem_Free(self->pop_buffer);
        self->push_buffer = NULL;
        self->pop_buffer = NULL;
        PyErr_NoMemory();
        return -1;
    }

    return 0;
}

// The __del__ method for PyLossyQueue objects
static void PyLossyQueue_dealloc(PyLossyQueue* self) {
    if (self->queue != NULL) {
        while (1) {
            size_t popped = try_pop_many(self->queue, (void **)self->pop_buffer,
              self->queue_size);

            if (popped == 0) {
                break;
            }
            for (size_t i = 0; i < popped; i++) {
                Py_DECREF(self->pop_buffer[i]);
            }
        }
        destroy_queue(self->queue);  // replace with actual queue destruction function
    }
    PyMem_Free(self->push_buffer);
    PyMem_Free(self->pop_buffer);
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

static PyObject*
PyLossyQueue_put_many(PyLossyQueue* self, PyObject* items_obj)
{
    PyObject* seq = PySequence_Fast(items_obj, "items must be iterable");
    Py_ssize_t count;
    Py_ssize_t i;
    size_t offset = 0;

    if (seq == NULL) {
        return NULL;
    }

    count = PySequence_Fast_GET_SIZE(seq);
    if (count == 0) {
        Py_DECREF(seq);
        Py_RETURN_NONE;
    }
    if ((size_t)count > self->queue_size) {
        Py_DECREF(seq);
        PyErr_SetString(PyExc_ValueError,
          "batch size must not exceed queue capacity");
        return NULL;
    }

    for (i = 0; i < count; i++) {
        PyObject* item = PySequence_Fast_GET_ITEM(seq, i);

        Py_INCREF(item);
        self->push_buffer[i] = item;
    }
    Py_DECREF(seq);

    while (offset < (size_t)count) {
        size_t pushed = try_push_many(self->queue,
          (void **)(self->push_buffer + offset),
          (size_t)count - offset);

        offset += pushed;
        if (offset == (size_t)count) {
            break;
        }

        size_t needed = (size_t)count - offset;
        size_t to_pop = needed;
        size_t popped;

        popped = try_pop_many(self->queue, (void **)self->pop_buffer, to_pop);
        for (size_t j = 0; j < popped; j++) {
            Py_DECREF(self->pop_buffer[j]);
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
    {"put_many", (PyCFunction)PyLossyQueue_put_many, METH_O, "Put multiple items into the queue"},
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
