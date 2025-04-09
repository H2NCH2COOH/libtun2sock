#include "pool.h"
#include <stdint.h>

//TODO: Optimize for when grow_step is 2 ** N

struct Pool_s
{
    void* (*realloc)(void*, size_t);

    size_t obj_size;
    int max_cnt;
    int grow_step;

    uint8_t** aa;
    size_t aa_size;
    size_t aa_cnt;

    size_t cnt;
};

PoolId POOLID_NULL = -1;

#define INFINIT_AA_STEP 64

Pool* pool_create(void* (*realloc)(void*, size_t), size_t obj_size, int max_cnt, int grow_step)
{
    if(realloc == NULL || obj_size == 0 || max_cnt == 0 || grow_step <= 0)
    {
        return NULL;
    }

    if(max_cnt > 0)
    {
        if(grow_step > max_cnt || (max_cnt % grow_step) != 0)
        {
            return NULL;
        }
    }

    Pool* p;
    if(max_cnt < 0)
    {
        p = realloc(NULL, sizeof(Pool));
        if(p == NULL)
        {
            return NULL;
        }

        p->aa = realloc(NULL, sizeof(uint8_t*) * INFINIT_AA_STEP);
        if(p->aa == NULL)
        {
            (void)realloc(p, 0);
            return NULL;
        }

        p->aa_size = INFINIT_AA_STEP;
    }
    else
    {
        size_t aa_size = max_cnt / grow_step;
        p = realloc(NULL, sizeof(Pool) + sizeof(uint8_t*) * aa_size);
        if(p == NULL)
        {
            return NULL;
        }

        p->aa = (uint8_t**)(p + 1);
        p->aa_size = aa_size;
    }

    p->realloc = realloc;
    p->obj_size = obj_size;
    p->max_cnt = max_cnt;
    p->grow_step = grow_step;

    p->aa[0] = realloc(NULL, obj_size * grow_step);
    if(p->aa[0] == NULL)
    {
        if(max_cnt < 0)
        {
            (void)realloc(p->aa, 0);
        }
        (void)realloc(p, 0);
        return NULL;
    }

    p->aa_cnt = 1;

    p->cnt = 0;

    return p;
}

void pool_delete(Pool* p)
{
    if(p == NULL)
    {
        return;
    }

    size_t i;
    for(i = 0; i < p->aa_cnt; ++i)
    {
        (void)p->realloc(p->aa[i], 0);
    }

    if(p->max_cnt < 0)
    {
        (void)p->realloc(p->aa, 0);
    }

    (void)p->realloc(p, 0);
}

void* pool_ref(Pool* p, PoolId id)
{
    if(p == NULL || id < 0 || (size_t)id >= p->cnt)
    {
        return NULL;
    }

    size_t ai = id / p->grow_step;
    size_t i = id % p->grow_step;

    return p->aa[ai] + p->obj_size * i;
}

int pool_get(Pool* p, PoolId* id, void** obj)
{
    if(id == NULL)
    {
        return -3;
    }

    if(p->max_cnt > 0 && p->cnt >= (size_t)p->max_cnt)
    {
        return -1;
    }

    size_t ai = p->cnt / p->grow_step;
    size_t i = p->cnt % p->grow_step;

    if(ai == p->aa_cnt)
    {
        if(p->aa_cnt == p->aa_size)
        {
            //assert(p->max_cnt < 0);
            uint8_t** aa = p->realloc(p->aa, sizeof(uint8_t*) * (p->aa_size + INFINIT_AA_STEP));
            if(aa == NULL)
            {
                return -2;
            }

            p->aa = aa;
            p->aa_size += INFINIT_AA_STEP;
        }

        uint8_t* a = p->realloc(NULL, p->obj_size * p->grow_step);
        if(a == NULL)
        {
            return -2;
        }

        p->aa[p->aa_cnt] = a;
        ++p->aa_cnt;
    }

    *id = p->cnt;
    ++p->cnt;

    if(obj != NULL)
    {
        *obj = p->aa[ai] + p->obj_size * i;
    }

    return 0;
}
