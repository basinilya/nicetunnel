#ifdef USE_MSAN

#define _GNU_SOURCE 1

#include <dlfcn.h>
#include <sys/stat.h>

static int (*next_stat) (const char *__restrict __file,
		 struct stat *__restrict __buf);

static int (*next_stat64) (const char *__restrict __file,
		 struct stat64 *__restrict __buf);

static int (*next_fstat64)(int __fd, struct stat64 *__buf);

#define STR1(x) #x
#define STR2(x) STR1(x)

// @suppress("Unused static function")
static __attribute__((constructor(101))) void __load_next_stat()  {
	//const char *s = STR2(stat);
	next_stat = dlsym(RTLD_NEXT, "stat");
	next_stat64 = dlsym(RTLD_NEXT, "stat64");
	next_fstat64 = dlsym(RTLD_NEXT, "fstat64");
}

static __THROW int _my_msan_stat(const char *__restrict __file, struct stat *__restrict __buf)  {
	if (!next_stat) {
		return -1;
	}
	struct stat tmp = { 0 }; // make msan happy
	int res = next_stat(__file, __buf ? &tmp : __buf);
	if (0 == res) {
		*__buf = tmp;
	}
	return res;
}

static __THROW int _my_msan_stat64(const char *__restrict __file, struct stat64 *__restrict __buf) {
	if (!next_stat64) {
		return -1;
	}
	struct stat64 tmp = { 0 }; // make msan happy
	int res = next_stat64(__file, __buf ? &tmp : __buf);
	if (0 == res) {
		*__buf = tmp;
	}
	return res;
}

static __THROW int _my_msan_fstat64(int __fd, struct stat64 *__buf) {
	if (!next_fstat64) {
		return -1;
	}
	struct stat64 tmp = { 0 }; // make msan happy
	int res = next_fstat64(__fd, __buf ? &tmp : __buf);
	if (0 == res) {
		*__buf = tmp;
	}
	return res;
}

__THROW __nonnull ((1, 2))
int stat_legacy (const char *__restrict __file,
		 struct stat *__restrict __buf)  {
	return _my_msan_stat(__file, __buf);
}

__THROW __nonnull ((1, 2))
int stat64 (const char *__restrict __file,
		 struct stat64 *__restrict __buf)  {
	return _my_msan_stat64(__file, __buf);
}

__THROW __nonnull ((2))
int fstat64 (int __fd, struct stat64 *__buf) {
	return _my_msan_fstat64(__fd, __buf);
}


#endif /* USE_MSAN */
