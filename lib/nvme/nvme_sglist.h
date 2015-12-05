#ifndef _NVME_SGLIST_H
#define _NVME_SGLIST_H

#include <stdio.h>

//typedef unsigned long long dma_addr_t;

enum dma_data_direction {
    DMA_BIDIRECTIONAL = 0,
    DMA_TO_DEVICE = 1,
    DMA_FROM_DEVICE = 2,
    DMA_NONE = 3,
};

struct scatterlist {
#ifdef CONFIG_DEBUG_SG
    unsigned long sg_magic;
#endif
    unsigned long page_link;
    unsigned int offset;
    unsigned int length;
    unsigned long long dma_address;
#ifdef CONFIG_NEED_SG_DMA_LENGTH
    unsigned int dma_length;
#endif
};

#define sg_dma_address(sg) ((sg)->dma_address)

#ifdef CONFIG_NEED_SG_DMA_LENGTH
#define sg_dma_len(sg) ((sg)->dma_length)
#else
#define sg_dma_len(sg) ((sg)->length)
#endif
#define sg_is_chain(sg) ((sg)->page_link & 0x01)
#define sg_is_last(sg) ((sg)->page_link & 0x02)
#define sg_chain_ptr(sg) \
    ((struct scatterlist *) ((sg)->page_link & ~0x03))

static struct scatterlist *sg_next(struct scatterlist *sg)
{
#ifdef CONFIG_DEBUG_SG
    BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
    if (sg_is_last(sg))
        return NULL;
    sg++;
    if (unlikely(sg_is_chain(sg)))
        sg = sg_chain_ptr(sg);
    return sg;
}
#define sg_is_chain(sg) ((sg)->page_link & 0x01)
#define sg_is_last(sg) ((sg)->page_link & 0x02)
#define sg_chain_ptr(sg) \
    ((struct scatterlist *) ((sg)->page_link & ~0x03))


static inline void sg_mark_end(struct scatterlist *sg)
{
#ifdef CONFIG_DEBUG_SG
    BUG_ON(sg->sg_magic != SG_MAGIC);
#endif
    /*
     * * Set termination bit, clear potential chain bit
     * */
    sg->page_link |= 0x02;
    sg->page_link &= ~0x01;
}

struct  page;
static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
{
    unsigned long page_link = sg->page_link & 0x3;
    /*
     * * In order for the low bit stealing approach to work, pages
     * * must be aligned at a 32-bit boundary as a minimum.
     * */
    //BUG_ON((unsigned long) page & 0x03);
    printf("PANIC ****** ****** FIX ME %p", page);

#ifdef CONFIG_DEBUG_SG
    BUG_ON(sg->sg_magic != SG_MAGIC);
    BUG_ON(sg_is_chain(sg));
#endif
    
    sg->page_link = page_link | (unsigned long) page;
}

static inline void sg_set_page(struct scatterlist *sg, struct page *page,
        unsigned int len, unsigned int offset)
{
#ifdef __KERNEL__
    sg_assign_page(sg, page);
#endif
    sg->offset = offset;
    sg->length = len;
}

static void sg_init_table(struct scatterlist *sgl, unsigned int nents)
{
    memset(sgl, 0, sizeof(*sgl) * nents);
#ifdef CONFIG_DEBUG_SG
    {
        unsigned int i;
        for (i = 0; i < nents; i++)
            sgl[i].sg_magic = SG_MAGIC;
    }
#endif
    sg_mark_end(&sgl[nents - 1]);
}

struct  device;
#define for_each_sg(sglist, sg, nr, __i) \
    for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
static int dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
        enum dma_data_direction dir)
{
    struct  scatterlist *s;
    int i;
    int size = 4096;
    for_each_sg(sg, s, nents, i) {
        s->dma_address = (unsigned long long)dev + (i*size);
    }
    return (nents);
}

#endif
