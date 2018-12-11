#include "array.h"
#include "stdio.h"

int main() {

  array_t *arr1 = array_from_str("10xxx001");
  array_t *arr2 = array_from_str("101xxxxx");
  array_t *arr3 = array_from_str("0000111x,101xxxxx");

  printf("arr1: %s\n",array_to_str(arr1,1,false));
  printf("arr2: %s\n",array_to_str(arr2,1,false));
  printf("arr3: %s\n",array_to_str(arr3,2,false));
  printf("arr intersect: %s\n",array_to_str(array_isect(arr1,arr2,1),1,0));
  int num = 0;
  array_t **result = array_cmpl(arr1,1,&num);
      //array_diff(arr1, arr2, 1, &num);
  printf("num is %d",num);
  for (int i = 0; i< num; i++) {
      printf("subtract result: %s\n",array_to_str(result[i],1,true));
      array_destroy(result[i]);
  }

  array_destroy(arr1);
  array_destroy(arr2);

  return 0;
}

