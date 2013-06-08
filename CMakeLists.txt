cmake_minimum_required( VERSION 2.6 )
set( VERBOSE 1 )

set( XNAME ssh2 )
add_definitions( -DWITH_TUNNEL )
# uncomment next line to enable runtime debug output
# add_definitions( -DDEBUG )

project( $XNAME )
set( TNAME ssh2_ )	
set( TSRC ssh2.c net.c )
set( CMAKE_C_FLAGS "-W -Wall -Wextra" )
include_directories( ${SOURCE_DIR} )
add_executable( ${TNAME} ${TSRC} )
set_target_properties( ${TNAME} PROPERTIES OUTPUT_NAME ${XNAME} )

# configure dependencies
include( FindPkgConfig )
pkg_check_modules( ZLIB REQUIRED zlib )
include_directories( ${ZLIB_INCLUDE_DIRS} )
target_link_libraries( ${TNAME} ${ZLIB_LIBRARIES} )
pkg_check_modules( LIBSSH2 REQUIRED libssh2 )
include_directories( ${LIBSSH2_INCLUDE_DIRS} )
target_link_libraries( ${TNAME} ${LIBSSH2_LIBRARIES} )

# add distclean make target 
add_custom_target( distclean 
	make clean 
	COMMAND rm -rf CMakeFiles CMakeCache.txt cmake_install.cmake Makefile 
)
