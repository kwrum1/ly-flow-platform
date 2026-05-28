PHP_ARG_ENABLE(ly_rasp, whether to enable LyFlow RASP support,
[  --enable-ly-rasp       Enable LyFlow RASP runtime hook extension])

if test "$PHP_LY_RASP" != "no"; then
  PHP_NEW_EXTENSION(ly_rasp, ly_rasp.c, $ext_shared)
fi
