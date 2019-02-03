#include <string.h>

#include <hydrogen.h>

#include <lua.h>
#include <lauxlib.h>

/* lhs = lua-hydrogen secretbox */

static int lhs_newkey(lua_State *L) {
	size_t len;
	const char *userkey = luaL_checklstring(L, 1, &len);
	luaL_argcheck(L, len == hydro_secretbox_KEYBYTES, 1, "invalid key length");
	uint8_t *key = lua_newuserdata(L, hydro_secretbox_KEYBYTES);
	memcpy(key, userkey, hydro_secretbox_KEYBYTES);
	luaL_setmetatable(L, "hydro_secretbox_key");
	return 1;
};

static int lhs_keygen(lua_State *L) {
	uint8_t *key = lua_newuserdata(L, hydro_secretbox_KEYBYTES);
	hydro_secretbox_keygen(key);
	luaL_setmetatable(L, "hydro_secretbox_key");
	return 1;
};

static int lhs_gc(lua_State *L) {
	uint8_t *key = luaL_checkudata(L, 1, "hydro_secretbox_key");
	hydro_memzero(key, hydro_secretbox_KEYBYTES);
	return 0;
};

static int lhs_keyasstring(lua_State *L) {
	const uint8_t *key = luaL_checkudata(L, 1, "hydro_secretbox_key");
	lua_pushlstring(L, (const char*)key, hydro_secretbox_KEYBYTES);
	return 1;
};

static int lhs_encrypt(lua_State *L) {
	size_t mlen, ctxlen;
	const uint8_t *m;
	const char *ctx;
	uint64_t msg_id;
	const uint8_t *key;
	uint8_t *c;
	luaL_Buffer b;

	m = (const uint8_t*)luaL_checklstring(L, 1, &mlen);
	msg_id = luaL_checkinteger(L, 2);
	ctx = luaL_checklstring(L, 3, &ctxlen);
	luaL_argcheck(L, ctxlen == hydro_secretbox_CONTEXTBYTES, 3, "invalid context length");
	key = luaL_checkudata(L, 4, "hydro_secretbox_key");

	c = (uint8_t*)luaL_buffinitsize(L, &b, hydro_secretbox_HEADERBYTES + mlen);
	hydro_secretbox_encrypt(c, m, mlen, msg_id, ctx, key);
	luaL_pushresultsize(&b, hydro_secretbox_HEADERBYTES + mlen);
	return 1;
};

static int lhs_decrypt(lua_State *L) {
	size_t clen, ctxlen;
	const uint8_t *c;
	const char *ctx;
	uint64_t msg_id;
	const uint8_t *key;
	luaL_Buffer b;

	c = (const uint8_t*)luaL_checklstring(L, 1, &clen);
	luaL_argcheck(L, clen >= hydro_secretbox_HEADERBYTES, 1, "ciphertext too short");
	msg_id = luaL_checkinteger(L, 2);
	ctx = luaL_checklstring(L, 3, &ctxlen);
	luaL_argcheck(L, ctxlen == hydro_secretbox_CONTEXTBYTES, 3, "invalid context length");
	key = luaL_checkudata(L, 4, "hydro_secretbox_key");

	uint8_t *m = (uint8_t*)luaL_buffinitsize(L, &b, clen - hydro_secretbox_HEADERBYTES);
	if (hydro_secretbox_decrypt(m, c, clen, msg_id, ctx, key) != 0) {
		lua_pushnil(L);
		return 1;
	}
	luaL_pushresultsize(&b, clen - hydro_secretbox_HEADERBYTES);
	return 1;
};

int luaopen_hydrogen_secretbox(lua_State *L) {
	static const luaL_Reg lib[] = {
		{"newkey", lhs_newkey},
		{"keygen", lhs_keygen},
		{"encrypt", lhs_encrypt},
		{"decrypt", lhs_decrypt},
		{NULL, NULL}
	};

	static const luaL_Reg methods[] = {
		{"asstring", lhs_keyasstring},
		{NULL, NULL}
	};

	luaL_newmetatable(L, "hydro_secretbox_key");
	luaL_newlib(L, methods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, lhs_gc);
	lua_setfield(L, -2, "__gc");
	lua_pop(L, 1);

	luaL_newlib(L, lib);
	return 1;
}

static int lhh_init(lua_State *L) {
	size_t ctxlen, keylen;
	const char *ctx;
	const uint8_t *key;
	hydro_hash_state *state;

	ctx = luaL_checklstring(L, 1, &ctxlen);
	luaL_argcheck(L, ctxlen == hydro_hash_CONTEXTBYTES, 1, "invalid context length");
	key = (const uint8_t*)luaL_optlstring(L, 2, NULL, &keylen);
	luaL_argcheck(L, key == NULL || keylen == hydro_hash_KEYBYTES, 2, "invalid key length");

	state = lua_newuserdata(L, sizeof(hydro_hash_state));

	if (hydro_hash_init(state, ctx, key) < 0)
		return luaL_error(L, "hydro_hash_update failure");

	luaL_setmetatable(L, "hydro_hash_state");
	return 1;
};

static int lhh_update(lua_State *L) {
	hydro_hash_state *state;
	size_t inlen;
	const char *in;

	state = luaL_checkudata(L, 1, "hydro_hash_state");
	in = luaL_checklstring(L, 2, &inlen);

	if (hydro_hash_update(state, in, inlen) < 0)
		return luaL_error(L, "hydro_hash_update failure");

	lua_pushboolean(L, 1);
	return 1;
};

static int lhh_final(lua_State *L) {
	hydro_hash_state *state;
	size_t outlen;
	uint8_t* out;
	luaL_Buffer b;

	state = luaL_checkudata(L, 1, "hydro_hash_state");
	outlen = luaL_optinteger(L, 2, hydro_hash_BYTES);

	out = (uint8_t*)luaL_buffinitsize(L, &b, outlen);
	if (hydro_hash_final(state, out, outlen) < 0)
		return luaL_error(L, "hydro_hash_final failure");
	luaL_pushresultsize(&b, outlen);
	return 1;
};

int luaopen_hydrogen_hash(lua_State *L) {
	static const luaL_Reg lib[] = {
		{"init", lhh_init},
		{NULL, NULL}
	};

	static const luaL_Reg methods[] = {
		{"update", lhh_update},
		{"final", lhh_final},
		{NULL, NULL}
	};

	luaL_newmetatable(L, "hydro_hash_state");
	luaL_newlib(L, methods);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luaL_newlib(L, lib);
	return 1;
}

static int lhr_u32(lua_State *L) {
	lua_pushinteger(L, hydro_random_u32());
	return 1;
}

static int lhr_uniform(lua_State *L) {
	uint32_t upper_bound = luaL_checkinteger(L, 1);
	lua_pushinteger(L, hydro_random_uniform(upper_bound));
	return 1;
}

static int lhr_buf(lua_State *L) {
	size_t len = luaL_checkinteger(L, 1);
	luaL_Buffer b;

	hydro_random_buf(luaL_buffinitsize(L, &b, len), len);

	luaL_pushresultsize(&b, len);
	return 1;
}

int luaopen_hydrogen_random(lua_State *L) {
	static const luaL_Reg lib[] = {
		{"u32", lhr_u32},
		{"uniform", lhr_uniform},
		{"buf", lhr_buf},
		{NULL, NULL}
	};
	luaL_newlib(L, lib);
	return 1;
}


static int lhu_bin2hex(lua_State *L) {
	size_t inlen;
	const uint8_t *in;
	char* out;
	luaL_Buffer b;

	in = (const uint8_t*)luaL_checklstring(L, 1, &inlen);

	out = luaL_buffinitsize(L, &b, inlen * 2 + 1);
	if (!hydro_bin2hex(out, inlen * 2 + 1, in, inlen))
		return luaL_error(L, "bin2hex overflow");

	luaL_pushresultsize(&b, inlen * 2);
	return 1;
};

static int lhu_hex2bin(lua_State *L) {
	size_t inlen;
	const char *in;
	const char *ignore;
	uint8_t *out;
	int outlen;
	const char *hex_end;
	luaL_Buffer b;

	in = luaL_checklstring(L, 1, &inlen);
	ignore = luaL_optstring(L, 2, NULL);

	out = (uint8_t*)luaL_buffinitsize(L, &b, (inlen >> 2) + 1);
	outlen = hydro_hex2bin(out, (inlen >> 2) + 1, in, inlen, ignore, &hex_end);
	if (outlen == -1) {
		lua_pushnil(L);
		lua_pushinteger(L, hex_end-in);
		return 2;
	}

	luaL_pushresultsize(&b, outlen);
	return 1;
};

int luaopen_hydrogen(lua_State *L) {
	static const luaL_Reg lib[] = {
		{"bin2hex", lhu_bin2hex},
		{"hex2bin", lhu_hex2bin},
		{NULL, NULL}
	};

	if (hydro_init() != 0)
		return luaL_error(L, "unable to initialize libhydrogen");


	lua_createtable(L, 0, 4 + sizeof(lib)/sizeof(lib[0]) - 1);

	luaL_requiref(L, "hydrogen.secretbox", luaopen_hydrogen_secretbox, 0);
	lua_setfield(L, -2, "secretbox");
	luaL_requiref(L, "hydrogen.hash", luaopen_hydrogen_hash, 0);
	lua_setfield(L, -2, "hash");
	luaL_requiref(L, "hydrogen.random", luaopen_hydrogen_random, 0);
	lua_setfield(L, -2, "random");
	luaL_setfuncs(L, lib, 0);

	lua_pushinteger(L, HYDRO_VERSION_MAJOR);
	lua_setfield(L, -2, "VERSION_MAJOR");
	lua_pushinteger(L, HYDRO_VERSION_MINOR);
	lua_setfield(L, -2, "VERSION_MINOR");

	return 1;
}
