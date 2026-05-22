#include "includes.h"
#include <openssl/evp.h>
#include <openssl/rc4.h>
#include <string.h>
#include <unistd.h>

#include "atomicio.h"
#include "xmalloc.h"
#include "log.h"
#include "obfuscate.h"

#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
# define SSH_EVP_MD_CTX_NEW() EVP_MD_CTX_new()
# define SSH_EVP_MD_CTX_FREE(ctx) EVP_MD_CTX_free((ctx))
#else
# define SSH_EVP_MD_CTX_NEW() EVP_MD_CTX_create()
# define SSH_EVP_MD_CTX_FREE(ctx) EVP_MD_CTX_destroy((ctx))
#endif

static RC4_KEY rc4_input;
static RC4_KEY rc4_output;

static const char *obfuscate_keyword = NULL;

#define OBFUSCATE_KEY_LENGTH 	16
#define OBFUSCATE_SEED_LENGTH	16
#define OBFUSCATE_HASH_ITERATIONS 6000
#define OBFUSCATE_MAX_PADDING	8192
#define OBFUSCATE_MAGIC_VALUE	0x0BF5CA7E

struct seed_msg {
	u_char seed_buffer[OBFUSCATE_SEED_LENGTH];
	u_int32_t magic;
	u_int32_t padding_length;
	u_char padding[];
};

static void generate_key_pair(const u_char *, u_char *, u_char *, int);
static void generate_key(const u_char *, const u_char *, u_int, u_char *, int);
static void set_keys(const u_char *, const u_char *);
static void initialize(const u_char *, int, int);
static int deobfuscate_seed(const u_char *, u_int32_t *, u_int32_t *, int);
static void read_forever(int);


/*
 * Server calls this
 */
void 
obfuscate_receive_seed(int sock_in)
{
	struct seed_msg seed;
	
	u_char padding_drain[OBFUSCATE_MAX_PADDING];
	u_int len;
	u_int32_t encrypted_magic;
	u_int32_t encrypted_padding_length;
	u_int32_t padding_length;
	int seed_state;

	len = atomicio(read, sock_in, &seed, sizeof(struct seed_msg));

	debug2("obfuscate_receive_seed: read %d byte seed message from client", len);
	if(len != sizeof(struct seed_msg))
		fatal("obfuscate_receive_seed: read failed");

	encrypted_magic = seed.magic;
	encrypted_padding_length = seed.padding_length;
	seed_state = deobfuscate_seed(seed.seed_buffer, &seed.magic,
	    &seed.padding_length, 0);
	if (seed_state == -1 && obfuscate_keyword != NULL) {
		seed.magic = encrypted_magic;
		seed.padding_length = encrypted_padding_length;
		seed_state = deobfuscate_seed(seed.seed_buffer, &seed.magic,
		    &seed.padding_length, 1);
		if (seed_state == 0)
			logit("Accepted obfuscated handshake using legacy keyword derivation");
	}

	if (seed_state == -1) {
		logit("Magic value check failed on obfuscated handshake.");
		read_forever(sock_in);
	}
	padding_length = ntohl(seed.padding_length);
	if (seed_state == -2) {
		logit("Illegal padding length %d for obfuscated handshake", ntohl(seed.padding_length));
		read_forever(sock_in);
	}
	len = atomicio(read, sock_in, padding_drain, padding_length);
	if(len != padding_length)
		fatal("obfuscate_receive_seed: read failed");
	debug2("obfuscate_receive_seed: read %d bytes of padding from client.", len);
	obfuscate_input(padding_drain, padding_length);
}

/*
 * Client calls this
 */
void
obfuscate_send_seed(int sock_out)
{
	struct seed_msg *seed; 
	int i;
	u_int32_t rnd = 0;
	u_int message_length;
	u_int padding_length;
	
	padding_length = arc4random() % OBFUSCATE_MAX_PADDING;
	message_length = padding_length + sizeof(struct seed_msg);
	seed = xmalloc(message_length);

	for(i = 0; i < OBFUSCATE_SEED_LENGTH; i++) {
		if(i % 4 == 0)
			rnd = arc4random();
		seed->seed_buffer[i] = rnd & 0xff;
		rnd >>= 8;
	}
	seed->magic = htonl(OBFUSCATE_MAGIC_VALUE);
	seed->padding_length = htonl(padding_length);
	for(i = 0; i < (int)padding_length; i++) {
		if(i % 4 == 0)
			rnd = arc4random();
		seed->padding[i] = rnd & 0xff;
	}
	initialize(seed->seed_buffer, 0, 0);
	obfuscate_output(((u_char *)seed) + OBFUSCATE_SEED_LENGTH,
		message_length - OBFUSCATE_SEED_LENGTH);
	debug2("obfuscate_send_seed: Sending seed message with %d bytes of padding", padding_length);
	if (atomicio(vwrite, sock_out, seed, message_length) != message_length)
		fatal("obfuscate_send_seed: write failed");
	memset(seed, 0, message_length);
	xfree(seed);

}

void
obfuscate_set_keyword(const char *keyword)
{
	debug2("obfuscate_set_keyword: Setting obfuscation keyword (length %lu)",
	    (unsigned long)strlen(keyword));
	obfuscate_keyword = keyword;
}

void
obfuscate_input(u_char *buffer, u_int buffer_len)
{
	RC4(&rc4_input, buffer_len, buffer, buffer);
}

void
obfuscate_output(u_char *buffer, u_int buffer_len)
{
	RC4(&rc4_output, buffer_len, buffer, buffer);
}

static void
initialize(const u_char *seed, int server, int use_legacy)
{
	u_char client_to_server_key[OBFUSCATE_KEY_LENGTH];
	u_char server_to_client_key[OBFUSCATE_KEY_LENGTH];
	
	generate_key_pair(seed, client_to_server_key, server_to_client_key,
	    use_legacy);

	if(server)
		set_keys(client_to_server_key, server_to_client_key);
	else
		set_keys(server_to_client_key, client_to_server_key);
}

static void
generate_key_pair(const u_char *seed, u_char *client_to_server_key,
    u_char *server_to_client_key, int use_legacy)
{
	generate_key(seed, (const u_char *)"client_to_server",
	    strlen("client_to_server"), client_to_server_key, use_legacy);
	generate_key(seed, (const u_char *)"server_to_client",
	    strlen("server_to_client"), server_to_client_key, use_legacy);
}

static void
generate_key(const u_char *seed, const u_char *iv, u_int iv_len,
    u_char *key_data, int use_legacy)
{
	EVP_MD_CTX *ctx;
	u_char md_output[EVP_MAX_MD_SIZE];
	u_int md_len;
	int i;
	u_char *buffer;
	u_char *p;
	u_int buffer_length;
	u_int hash_length;
	u_int keyword_len = 0;

	buffer_length = OBFUSCATE_SEED_LENGTH + iv_len;
	if(!use_legacy && obfuscate_keyword) {
		keyword_len = strlen(obfuscate_keyword);
		buffer_length += keyword_len;
	}
	hash_length = buffer_length;

	p = buffer = xmalloc(buffer_length);
	ctx = SSH_EVP_MD_CTX_NEW();
	if (ctx == NULL)
		fatal("Cannot allocate digest context");

	memcpy(p, seed, OBFUSCATE_SEED_LENGTH);
	p += OBFUSCATE_SEED_LENGTH;

	if(keyword_len != 0) {
		memcpy(p, obfuscate_keyword, keyword_len);
		p += keyword_len;
	}
	memcpy(p, iv, iv_len);

	if (!EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) ||
	    !EVP_DigestUpdate(ctx, buffer, hash_length) ||
	    !EVP_DigestFinal_ex(ctx, md_output, &md_len))
		fatal("Cannot derive obfuscation key");

	memset(buffer, 0, buffer_length);
	xfree(buffer);

	for(i = 0; i < OBFUSCATE_HASH_ITERATIONS; i++) {
		if (!EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) ||
		    !EVP_DigestUpdate(ctx, md_output, md_len) ||
		    !EVP_DigestFinal_ex(ctx, md_output, &md_len))
			fatal("Cannot derive obfuscation key");
	}
	SSH_EVP_MD_CTX_FREE(ctx);

	if(md_len < OBFUSCATE_KEY_LENGTH) 
		fatal("Cannot derive obfuscation keys from hash length of %d", md_len);

	memcpy(key_data, md_output, OBFUSCATE_KEY_LENGTH);
	memset(md_output, 0, sizeof(md_output));
}

static int
deobfuscate_seed(const u_char *seed, u_int32_t *magicp,
    u_int32_t *padding_lengthp, int use_legacy)
{
	initialize(seed, 1, use_legacy);
	obfuscate_input((u_char *)magicp, 8);

	if (OBFUSCATE_MAGIC_VALUE != ntohl(*magicp))
		return -1;
	if (ntohl(*padding_lengthp) > OBFUSCATE_MAX_PADDING)
		return -2;
	return 0;
}

static void
set_keys(const u_char *input_key, const u_char *output_key)
{
	RC4_set_key(&rc4_input, OBFUSCATE_KEY_LENGTH, input_key);
	RC4_set_key(&rc4_output, OBFUSCATE_KEY_LENGTH, output_key);
}

static void
read_forever(int sock_in)
{
	u_char discard_buffer[1024];

	while(atomicio(read, sock_in, discard_buffer, sizeof(discard_buffer)) > 0)
		;
	cleanup_exit(255);
}
