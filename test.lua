local hydrogen = require "hydrogen"

do
	local secretbox = hydrogen.secretbox
	pcall(function()
		secretbox.newkey("123456789123")
	end)
	local key = secretbox.keygen()
	local plaintext = "my message"
	local ciphertext = secretbox.encrypt(plaintext, 0, "8bytectx", key)
	assert(secretbox.decrypt(ciphertext, 0, "8bytectx", key) == plaintext)
end

do
	local hash = hydrogen.hash
	local state = hash.init("8bytectx", "some_32_byte_key________________")
	state:update("some data")
	print(state:final())
end

do
	assert(hydrogen.bin2hex("\0") == "00")
	assert(hydrogen.hex2bin("00") == "\0")
end
