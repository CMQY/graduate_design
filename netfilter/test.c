#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>

struct test{
    struct list_head list;
    int data;
};

static int main_init(void)
{
/******************************************************************************************
 *
 * list for each
 *
 ******************************************************************************************
    struct test *first;
    struct test *temp;
    struct test *var;

    first = (struct test *)kmalloc(sizeof(struct test), GFP_KERNEL);
    first->data=1;
    INIT_LIST_HEAD(&first->list);
    
    temp = (struct test *)kmalloc(sizeof(struct test), GFP_KERNEL);
    temp->data=2;
    INIT_LIST_HEAD(&first->list);

    list_add(&(temp->list), &(first->list));

    printk("[LSP]%d %d\n",first->data,container_of(first->list.next, struct test, list)->data);

    list_for_each_entry(var, &first->list, list)
    {
        printk(KERN_ALERT "[LSP] %d\n",var->data);
    }
    return 0;

******************************************************************************************/
}

static void main_exit(void)
{
}
module_init(main_init);
module_exit(main_exit);
