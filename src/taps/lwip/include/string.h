#if __has_builtin(__builtin_memset)
#define memset __builtin_memset
#endif

#if __has_builtin(__builtin_memcpy)
#define memcpy __builtin_memcpy
#endif

#if __has_builtin(__builtin_memmove)
#define memmove __builtin_memmove
#endif

#if __has_builtin(__builtin_memcmp)
#define memcmp __builtin_memcmp
#endif

#if __has_builtin(__builtin_strcmp)
#define strcmp __builtin_strcmp
#endif

#if __has_builtin(__builtin_strcpy)
#define strcpy __builtin_strcpy
#endif
