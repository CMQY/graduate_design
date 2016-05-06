/****************************************************************************************
 *
 *      Display an IP address in readable format,in old kernel.
 *      newer kernel please refer to /Documentation/printk-formats.txt
 *
 ***************************************************************************************/


#if defined(__LITTLE_ENDIAN)
#define HIPQUAD(addr) \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]
#endif
/****************************************************************************************
 *
 * get attr for nlattr pointer
 *
 ***************************************************************************************/



