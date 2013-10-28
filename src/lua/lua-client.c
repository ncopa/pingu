#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "pingu_adm.h"

#define LIBNAME "pingu.client"

#if LUA_VERSION_NUM < 502
#  define luaL_newlib(L,l) (lua_newtable(L), luaL_register(L,NULL,l))
#endif

static int pusherror(lua_State *L, const char *info)
{
	lua_pushnil(L);
	if (info == NULL)
		lua_pushstring(L, strerror(errno));
	else
		lua_pushfstring(L, "%s: %s", info, strerror(errno));
	lua_pushinteger(L, errno);
	return 3;
}

static int pushfile(lua_State *L, int fd, const char *mode)
{
	FILE **f = (FILE **)lua_newuserdata(L, sizeof(FILE *));
	*f = NULL;
	luaL_getmetatable(L, "FILE*");
	lua_setmetatable(L, -2);
	*f = fdopen(fd, mode);
	return (*f != NULL);
}

static int Padm_open(lua_State *L)
{
	const char *socket_path = luaL_optstring(L, 1, DEFAULT_ADM_SOCKET);
	struct sockaddr_un sun;
	int fd, ret;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, socket_path, sizeof(sun.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return pusherror(L, "socket");

	if (connect(fd, (struct sockaddr *) &sun, sizeof(sun)) < 0) {
		ret = pusherror(L, socket_path);
		goto close_err;
	}

	return pushfile(L, fd, "r+");

close_err:
	close(fd);
	return ret;
}

static const luaL_Reg reg_pingu_methods[] = {
	{"open",	Padm_open},
	{NULL,	NULL},
};


LUALIB_API int luaopen_pingu_client(lua_State *L)
{
	luaL_newlib(L, reg_pingu_methods);
	lua_pushliteral(L, "version");
	lua_pushliteral(L, PINGU_VERSION);
	lua_settable(L, -3);
	return 1;
}
