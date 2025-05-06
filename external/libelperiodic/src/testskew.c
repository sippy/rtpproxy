#include <sys/time.h>
#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

//extern int optind;

#include "elperiodic.h"
#include "prdic_timespecops.h"

static void
usage(void)
{

    fprintf(stderr, "usage: testskew [-vqm] freq ival\n");
    exit(1);
}

#define silence(msg) (!(qflag) ? (msg) : "")

int
main(int argc, char * const argv[])
{
    void *prd;
    int i, ch, vflag, qflag, mflag, Sflag, pflag, wflag;
    double freq, duration, skew, fval, Lmin, Lmax, Lcur;
    time_t ncycles, mcycles;

    vflag = 0;
    qflag = 0;
    mflag = 0;
    Sflag = 0;
    pflag = 0;
    fval = 0.0;
    Lmin = 0.0;
    Lmax = 0.0;
    wflag = 0;
    while ((ch = getopt(argc, argv, "vqmSf:pLw")) != -1) {
         switch (ch) {
         case 'v':
             vflag = 1;
             break;

         case 'q':
             qflag = 1;
             break;

         case 'm':
             mflag = 1;
             break;

         case 'S':
             Sflag = 1;
             break;

         case 'p':
             pflag = 1;
             break;

         case 'f':
             fval = atof(optarg);
             break;

         case 'L':
             Lmin = 0.0;
             Lmax = 1.1;
             break;

         case 'w':
             wflag = 1;
             break;

         case '?':
         default:
             usage();
         }
    }
    argc -= optind;
    argv += optind;
    if (argc == 0 || (argc % 2) != 0) {
        usage();
    }
    prd = NULL;
    do {
        freq = atof(argv[0]);
        duration = atof(argv[1]);
        for (Lcur = Lmin; Lcur <= Lmax; Lcur += 0.05) {
            int wcycles = 0;
            int bnum;
            time_t startncycles = 0;

            double dperiod = Lcur / freq;
            if (prd == NULL) {
                prd = prdic_init(freq, 0.0);
                assert(prd != NULL);
                if (pflag)
                    assert(prdic_set_det_type(prd, 0, PRDIC_DET_PHASE) == PRDIC_DET_FREQ);
                bnum = 0;
            } else {
                bnum = prdic_addband(prd, freq);
                assert(bnum > 0);
                prdic_useband(prd, bnum);
            }
            assert(prdic_islocked(prd) == 0);
            if (fval != 0.0) {
                prdic_set_fparams(prd, fval);
            }
            ncycles = 0;
            for (i = 0; i - wcycles < (freq * duration); i++) {
                if (dperiod > 0) {
                    struct timespec tsleep;

                    dtime2timespec(dperiod, &tsleep);
                    nanosleep(&tsleep, NULL);
                }
                prdic_procrastinate(prd);
                if (ncycles == 0 && wflag) {
                    if (!prdic_islocked(prd)) {
                        wcycles++;
                        if (wcycles >= (freq * duration)) {
                            break;
                        }
                        if (vflag != 0) {
                            printf("unlocked: %lld\r", (long long)wcycles);
                            fflush(stdout);
                        }
                        startncycles = prdic_getncycles_ref(prd);
                        continue;
                    }
                    if (wcycles > 0 && vflag != 0) {
                        printf("\n");
                        fflush(stdout);
                    }
                }
                ncycles = prdic_getncycles_ref(prd);
                if (vflag != 0) {
                    printf("%lld\r", (long long)(ncycles - startncycles));
                    fflush(stdout);
                }
            }
            ncycles -= startncycles;
            if (vflag != 0) {
                printf("\n");
            }
            if (mflag == 0) {
                skew = 1.0 - ((double)ncycles / (freq * duration));
                if (Lmax > 0 && !qflag) {
                    printf("load: %.1f%% (actual), %.1f%% (measured), ",
                      Lcur * 100.0, prdic_getload(prd) * 100.0);
                }
                if (Sflag == 0) {
                    printf("%s%f%s\n", silence("skew: "), skew * 100.0, silence("%"));
                } else {
                    printf("%s%d\n", silence("skew: "), (int)(skew * 100000.0));
                }
            } else {
                mcycles = ncycles - (freq * duration);
                printf("%s%jd\n", silence("missed cycles: "), (intmax_t)mcycles);
            }
            fflush(stdout);
            if (argc == 2) {
                prdic_free(prd);
                prd = NULL;
            }
        }
        argv += 2;
        argc -= 2;
    } while (argc > 0);

    return (0);
}
