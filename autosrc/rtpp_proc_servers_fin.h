/* Auto-generated by genfincode_stat.sh - DO NOT EDIT! */
#if !defined(_rtpp_proc_servers_fin_h)
#define _rtpp_proc_servers_fin_h
#if !defined(RTPP_AUTOTRAP)
#define RTPP_AUTOTRAP() abort()
#else
extern int _naborts;
#endif
#if defined(RTPP_DEBUG)
struct rtpp_proc_servers;
void rtpp_proc_servers_fin(struct rtpp_proc_servers *);
#else
#define rtpp_proc_servers_fin(arg) /* nop */
#endif
#if defined(RTPP_FINTEST)
void rtpp_proc_servers_fintest(void);
#endif /* RTPP_FINTEST */
#endif /* _rtpp_proc_servers_fin_h */
