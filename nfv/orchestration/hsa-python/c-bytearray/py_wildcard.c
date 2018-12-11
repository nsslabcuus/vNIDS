#include <Python.h>
#include <array.h>
#include <stdbool.h>

#ifdef PYTHON2_6
void array_destroy_cobject (void* object)
{
  PyMem_Free(object);
}
#define GetPointer(obj,exp) PyCObject_AsVoidPtr(obj)
#define NewCap(ptr,exp) PyCObject_FromVoidPtr(ptr,array_destroy_cobject)
#else
void array_destroy_capsule (PyObject* object)
{
  PyMem_Free(PyCapsule_GetPointer(object,"wc_expression"));
}
#define GetPointer(obj,exp) PyCapsule_GetPointer(obj,exp)
#define NewCap(ptr,exp) PyCapsule_New(ptr,exp,array_destroy_capsule)
#endif

static PyObject *
py_create(PyObject *self, PyObject* args) {
  int L,bit;
  if (!PyArg_ParseTuple(args, "ii", &L, &bit)) {
    return NULL;
  }
  bit = bit %4;
  array_t *result = array_create(L,bit);
  return NewCap(result,"wc_expression");
}

static PyObject *
py_copy(PyObject *self, PyObject* args) {
  int L;
  PyObject *object;
  if (!PyArg_ParseTuple(args, "Oi", &object, &L)) {
    return NULL;
  }
  array_t *result = array_copy(
      (array_t *)GetPointer(object,"wc_expression"),L
      );
  return NewCap(result,"wc_expression");
}

static PyObject *
py_to_string(PyObject *self, PyObject* args) {
  PyObject *object;
  int L,pretty;
  if (!PyArg_ParseTuple(args, "Oii", &object, &L, &pretty)) {
    return NULL;
  }
  bool p = (pretty != 0);
  char *result = array_to_str(
      (array_t *)GetPointer(object,"wc_expression"),L,p
      );
  return Py_BuildValue("s",result);
}

static PyObject *
py_from_string(PyObject *self, PyObject* args) {
  char *str;
  if (!PyArg_ParseTuple(args, "s", &str)) {
    return NULL;
  }
  array_t *result = array_from_str(str);
  return NewCap(result,"wc_expression");
}

static PyObject *
py_from_int(PyObject *self, PyObject* args) {
  long long val;
  int L;
  if (!PyArg_ParseTuple(args, "Li", &val, &L)) {
    return NULL;
  }
  array_t *result = array_from_int(val,L);
  return NewCap(result,"wc_expression");
}

static PyObject *
py_and(PyObject *self, PyObject* args) {
  PyObject *object1;
  PyObject *object2;
  int L;
  if (!PyArg_ParseTuple(args, "OOi", &object1, &object2, &L)) {
    return NULL;
  }
  array_t* result = array_and(
      (array_t *)GetPointer(object1,"wc_expression"),
      (array_t *)GetPointer(object2,"wc_expression"),L);
  return NewCap(result,"wc_expression");
}

static PyObject *
py_or(PyObject *self, PyObject* args) {
  PyObject *object1;
  PyObject *object2;
  int L;
  if (!PyArg_ParseTuple(args, "OOi", &object1, &object2, &L)) {
    return NULL;
  }
  array_t* result = array_or(
      (array_t *)GetPointer(object1,"wc_expression"),
      (array_t *)GetPointer(object2,"wc_expression"),L);
  return NewCap(result,"wc_expression");
}

static PyObject *
py_not(PyObject *self, PyObject* args) {
  PyObject * object;
  int L;
  if (!PyArg_ParseTuple(args, "Oi", &object, &L)) {
    return NULL;
  }
  array_t* result = array_not(
      (array_t *)GetPointer(object,"wc_expression"),L);
  return NewCap(result,"wc_expression");
}

static PyObject *
py_isect(PyObject *self, PyObject* args) {
  PyObject *object1;
  PyObject *object2;
  int L;
  if (!PyArg_ParseTuple(args, "OOi", &object1, &object2, &L)) {
    return NULL;
  }
  array_t* result = array_isect(
      (array_t *)GetPointer(object1,"wc_expression"),
      (array_t *)GetPointer(object2,"wc_expression"),L);
  if (result) {
      return NewCap(result,"wc_expression");
  } else {
      Py_INCREF(Py_None);
      return Py_None;
  }
}

static PyObject *
py_compl(PyObject *self, PyObject* args) {
  PyObject * object;
  int L;
  if (!PyArg_ParseTuple(args, "Oi", &object, &L)) {
    return NULL;
  }
  int len;
  array_t** result = array_cmpl(
      (array_t *)GetPointer(object,"wc_expression"),L,&len);
  PyObject *compls = PyList_New(len);
  for (int i= 0; i < len; i++) {
      PyList_SetItem(compls,i,
          NewCap(result[i],"wc_expression"));
  }
  free(result);
  return compls;
}

static PyObject *
py_diff(PyObject *self, PyObject* args) {
  PyObject *object1;
  PyObject *object2;
  int L;
  if (!PyArg_ParseTuple(args, "OOi", &object1, &object2, &L)) {
    return NULL;
  }
  int len;
  array_t** result = array_diff(
      (array_t *)GetPointer(object1,"wc_expression"),
      (array_t *)GetPointer(object2,"wc_expression"),L,&len);
  PyObject *diffs = PyList_New(len);
  for (int i= 0; i < len; i++) {
      PyList_SetItem(diffs,i,
          NewCap(result[i],"wc_expression"));
  }
  free(result);
  return diffs;
}

static PyObject *
py_rw(PyObject *self, PyObject* args) {
  PyObject *object1;
  PyObject *object2;
  PyObject *object3;
  int L;
  if (!PyArg_ParseTuple(args, "OOOi", &object1, &object2, &object3, &L)) {
    return NULL;
  }
  int card;
  array_t* result = array_rw(
      (array_t *)GetPointer(object1,"wc_expression"),
      (array_t *)GetPointer(object2,"wc_expression"),
      (array_t *)GetPointer(object3,"wc_expression"),L,&card);
  PyObject *res = PyTuple_New(2);
  PyTuple_SetItem(res,0,NewCap(result,"wc_expression"));
  PyTuple_SetItem(res,1,Py_BuildValue("i",card));
  return res;
}

static PyObject *
py_is_subset(PyObject *self, PyObject* args) {
  PyObject *object1;
  PyObject *object2;
  int L;
  if (!PyArg_ParseTuple(args, "OOi", &object1, &object2, &L)) {
    return NULL;
  }
  bool result = array_is_sub(
      (array_t *)GetPointer(object1,"wc_expression"),
      (array_t *)GetPointer(object2,"wc_expression"),L);
  return Py_BuildValue("i",(int)result);
}

static PyObject *
py_is_equal(PyObject *self, PyObject* args) {
  PyObject *object1;
  PyObject *object2;
  int L;
  if (!PyArg_ParseTuple(args, "OOi", &object1, &object2, &L)) {
    return NULL;
  }
  bool result = array_is_equal(
      (array_t *)GetPointer(object1,"wc_expression"),
      (array_t *)GetPointer(object2,"wc_expression"),L);
  return Py_BuildValue("i",(int)result);
}

static PyObject *
py_set_byte(PyObject *self, PyObject* args) {
  PyObject * object;
  int b,pos,L;
  if (!PyArg_ParseTuple(args, "Oiii", &object, &b, &pos, &L)) {
    return NULL;
  }
  array_set_byte(
      (array_t *)GetPointer(object,"wc_expression"),(array_t)b,pos,L);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
py_set_bit(PyObject *self, PyObject* args) {
  PyObject * object;
  int b,pos1,pos2,L;
  if (!PyArg_ParseTuple(args, "Oiiii", &object, &b, &pos1, &pos2, &L)) {
    return NULL;
  }
  array_set_bit(
      (array_t *)GetPointer(object,"wc_expression"),(array_t)b,
      pos1,pos2,L);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
py_get_byte(PyObject *self, PyObject* args) {
  PyObject * object;
  int res,pos,L;
  if (!PyArg_ParseTuple(args, "Oii", &object, &pos, &L)) {
    return NULL;
  }
  res = array_get_byte(
      (array_t *)GetPointer(object,"wc_expression"),pos,L);
  return Py_BuildValue("i",res);
}

static PyObject *
py_get_bit(PyObject *self, PyObject* args) {
  PyObject * object;
  int res,pos1,pos2,L;
  if (!PyArg_ParseTuple(args, "Oiii", &object, &pos1, &pos2, &L)) {
    return NULL;
  }
  res = array_get_bit(
      (array_t *)GetPointer(object,"wc_expression"),pos1,pos2,L);
  return Py_BuildValue("i",res);
}

static PyObject *
py_pickle(PyObject *self, PyObject* args)
{
  int L;
  PyObject *object;
  if (!PyArg_ParseTuple(args, "Oi", &object, &L)) {
    return NULL;
  }
  int len = (int)ALLOC_WORDS(L);
  reg_t *words = (reg_t *)GetPointer(object,"wc_expression");
  PyObject *nums = PyList_New(len);
  for (int i= 0; i < len; i++) {
      PyList_SetItem(nums,i,Py_BuildValue("L",words[i]));
  }
  return nums;
}

static PyObject *
py_unpickle(PyObject *self, PyObject* args)
{
  PyObject *list;
  if (!PyArg_ParseTuple(args, "O", &list)) {
    return NULL;
  }
  Py_ssize_t l = PyList_Size(list);
  reg_t *res = (reg_t *)PyMem_Malloc ( l * sizeof (reg_t));
  for (Py_ssize_t i=0; i < l; i++) {
      reg_t num = (reg_t)PyLong_AsLongLong(PyList_GetItem(list,i));
      res[i] = num;
  }
  return NewCap(res,"wc_expression");
}

static PyMethodDef WildcardMethods[] = {
  {"_wildcard_create", py_create, METH_VARARGS, "creates a wildcard expression"},
  {"_wildcard_copy", py_copy, METH_VARARGS, "copies a wildcard expression"},
  {"_wildcard_to_string", py_to_string, METH_VARARGS, "converts a wildcard expression to string"},
  {"_wildcard_from_string", py_from_string, METH_VARARGS, "converts a string to wildcard expression"},
  {"_wildcard_from_int", py_from_int, METH_VARARGS, "converts an integer to wildcard expression"},
  {"_wildcard_logical_and", py_and, METH_VARARGS, "find logical AND of two wildcard expressions"},
  {"_wildcard_logical_or", py_or, METH_VARARGS, "find logical OR of two wildcard expressions"},
  {"_wildcard_logical_not", py_not, METH_VARARGS, "find logical NOT of a wildcard expression"},
  {"_wildcard_isect", py_isect, METH_VARARGS, "find intersection of two wildcard expressions"},
  {"_wildcard_compl", py_compl, METH_VARARGS, "find complement of a wildcard expression"},
  {"_wildcard_diff", py_diff, METH_VARARGS, "find A-B where A is first argument and B is second argument, both wildcard expressions."},
  {"_wildcard_rewrite", py_rw, METH_VARARGS, "rewrites a wildcard using mask and rewrite wildcards. returns a new rewritten wildcard and cardinality."},
  {"_wildcard_is_subset", py_is_subset, METH_VARARGS, "checks if first arg is a subset of second arg."},
  {"_wildcard_is_equal", py_is_equal, METH_VARARGS, "checks if arguments are equal."},
  {"_wildcard_set_byte", py_set_byte, METH_VARARGS, "set a byte in the array."},
  {"_wildcard_set_bit", py_set_bit, METH_VARARGS, "set a bit within a byte in the array."},
  {"_wildcard_get_byte", py_get_byte, METH_VARARGS, "get a byte in the array."},
  {"_wildcard_get_bit", py_get_bit, METH_VARARGS, "get a bit in the array."},
  {"_wildcard_pickle", py_pickle, METH_VARARGS, "pickle."},
  {"_wildcard_unpickle", py_unpickle, METH_VARARGS, "unpickle."},
  {NULL, NULL, 0, NULL}
};

void initc_wildcard(void){
  (void) Py_InitModule("c_wildcard", WildcardMethods);
}
