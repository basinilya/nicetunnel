Requires a glib compiled with msan

      sed -i \
        -e "s/'-Wl,-no-undefined',//" \
        glib/gio/fam/meson.build
    
      CFLAGS+=" -fsanitize=memory -fPIE "
      CXXFLAGS+=" -fsanitize=memory -fPIE "
      LDFLAGS+=" -pie"
    
      CC="clang"
      CXX="clang++"
      LDFLAGS=$LDFLAGS CXXFLAGS=$CXXFLAGS CC=$CC CXX=$CXX \
      arch-meson glib build \
        --buildtype debug \
        -D tests=false \
        -D b_lundef=false \
        -D glib_debug=disabled \
        -D selinux=disabled \
        -D man=false \
        -D gtk_doc=false
    
    
    # create an rpath directory with all shared libraries
    mkdir /home/il/glib-msan-lib
    find . ! -type d "(" -name "*.so" -o "(" -name "*.so.*" ! -name "*.py" ! -name "*.symbols" ")" ")" | while read -r so; do ln -sf $PWD/$so /home/il/glib-msan-lib/; done
    
    
    configure with:
    
    CPPFLAGS="-DUSE_MSAN" CFLAGS="-g -O0 -fsanitize=memory -fPIE" LDFLAGS="-pie -Wl,-rpath=/home/il/glib-msan-lib" CC="clang"
    
