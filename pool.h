#ifndef _POOL_H_
#define _POOL_H_

#include <stddef.h>

typedef struct Pool_s Pool;

typedef int PoolId; //Must be able to be tested using "=="
extern PoolId POOLID_NULL; //The NULL id

/***
 * Create a new pool
 * @param realloc           The memory alloction function
 * @param obj_size          The size of one object
 * @param max_cnt           The maximum count of objects in this pool
 *                          -1 means the pool will grow indefinitely
 * @param grow_step         The number of new objects to allocate when the pool is full and at start
 *                          max_cnt (if positive) must be divisible by grow_step
 * @return                  Success: The pointer to the newly created pool
 *                          Failure: NULL
 */
Pool* pool_create(void* (*realloc)(void*, size_t), size_t obj_size, int max_cnt, int grow_step);

/***
 * Free a pool
 * @param p                 The pool to free
 */
void pool_delete(Pool* p);

/***
 * Get the object pointer from the pool using the id
 * @param p                 The pool
 * @param id                The id
 * @return                  Success: The pointer to the object
 *                          Failure: NULL
 */
void* pool_ref(Pool* p, PoolId id);

/***
 * Get a new object from the pool
 * @param p                 The pool
 * @param id                Will store the id of the new object inside
 *                          Must not be NULL
 * @param obj               If not NULL, will store the pointer to the new object inside when success
 *                          Save a call to pool_ref()
 * @return                  0  Success
 *                          -1 Reached maximum count
 *                          -2 Not enough memory
 *                          -X Other errors
 */
 int pool_get(Pool* p, PoolId* id, void** obj);

#endif /* _POOL_H_ */
