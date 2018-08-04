/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_md5.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/18 01:54:31 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/04 11:15:01 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_MD5
# define FT_SSL_MD5

# include "libft.h"
# include <stdio.h> //
# include <unistd.h>
# include <stdlib.h>
# include <assert.h> //
# include <fcntl.h>
# include <sys/types.h>

# define INLINE __attribute__((always_inline)) inline
# define NORETURN __attribute__((noreturn)) void

# define USAGE "usage: ft_ssl command [command opts] [command args]"

/*
** Supported hash algorithm names
*/

typedef enum	e_cmd_type
{
	MD5 = 0,
	SHA256,
	SHA224,
	SHA512,
	BASE64,
	DES,
	SUPPORTED_TYPES,
	// please add more
}				t_cmd_type;

typedef enum	e_cmd_kind
{
	HASH = 0,
	SYMMETRIC_ENCRYPTION,
	ASYMMETRIC_ENCRYPTION,
	SUPPORTED_KINDS,
}				t_cmd_kind;

typedef union	u_flags t_flags;
typedef struct	s_command_line t_command_line;
typedef t_flags	*(*t_cmd_parse)(int argc, char **argv, t_command_line *cmd);
typedef uint32_t *(*t_hash_function)(void*, uint64_t);
typedef unsigned char *(*t_system_hash_function)(const void*, unsigned int, unsigned char*);
typedef void	(*t_cmd_executor)(t_command_line *cmd);


typedef struct s_hash_identity {
	t_hash_function			hash_function;
	t_system_hash_function	system_hash_function;
	uint64_t				digest_size;
}				t_hash_identity;

typedef uint8_t t_se_key;
typedef uint8_t	*(*t_se_encode_function)(uint8_t *clear, uint64_t len, t_se_key *key);
typedef uint8_t	*(*t_se_decode_function)(uint8_t *cipher, uint64_t len, t_se_key *key);

typedef struct	s_se_identity
{
	t_se_encode_function	encode_function;
	t_se_decode_function	decode_function;
}				t_se_identity;

typedef struct	s_ae_identity
{
	char	*key; // non contractual
	char	*salt; // non contractual
}				t_ae_identity;

typedef union	u_cmd_internal
{
	t_hash_identity	hash;
	t_se_identity	se;
	t_ae_identity	ae;
}				t_cmd_internal;

typedef struct	s_cmd_identity
{
	char			*name;
	t_cmd_parse		cmd_parse_function;
	t_cmd_executor	cmd_executor;
	t_cmd_internal	info;
	t_cmd_type		type;
	t_cmd_kind		kind;
}				t_cmd_identity;

extern const t_hash_identity	g_supported_hashs[SUPPORTED_TYPES];

extern const t_cmd_identity		g_supported_cmds[SUPPORTED_TYPES];

/*
** Command line parsing
*/

typedef int32_t (*t_f_parse_callback)(t_command_line *);

typedef struct	s_parse_callback {
	t_f_parse_callback	callback;
	char				flag_c;
	uint8_t				pad[7];
}				t_parse_callback;

typedef struct	s_sha256_flags
{
	uint8_t	p : 1;
	uint8_t	q : 1;
	uint8_t	r : 1;
	uint8_t	s : 1;
	uint8_t	pad : 4;
}				t_sha256_flags;

typedef struct	s_md5_flags
{
	uint8_t	p : 1;
	uint8_t	q : 1;
	uint8_t	r : 1;
	uint8_t	s : 1;
	uint8_t	pad : 4;
}				t_md5_flags;

typedef struct	s_base64_flags
{
	uint8_t	d : 1;
	uint8_t	e : 1;
	uint8_t	i : 1;
	uint8_t	o : 1;
	uint8_t	pad : 4;
}				t_base64_flags;

typedef struct	s_des_flags
{
	uint8_t	a : 1;
	uint8_t	d : 1;
	uint8_t	e : 1;
	uint8_t	i : 1;
	uint8_t	k : 1;
	uint8_t	o : 1;
	uint8_t	p : 1;
	uint8_t	s : 1;
	uint8_t	v : 1;
	uint8_t	pad : 7;
}				t_des_flags;

typedef union	u_flags
{
	t_md5_flags		md5;
	t_sha256_flags	sha256;
	t_base64_flags	base64;
	t_des_flags		des;
}				t_flags;

typedef struct	s_hash_cmd
{
	uint64_t				nbr_strings;
	char					**strings_to_hash;
	uint64_t				nbr_files;
	char					**filenames;
	t_flags					flags;
	uint8_t					pad[6];
}				t_hash_cmd;

typedef struct	s_se_cmd
{
	char		*input_file;
	char		*output_file;
	char		*key;
	char		*password;
	char		*init_vector;
	char		*salt;
	t_flags		flags;
	uint8_t		pad[6];
}				t_se_cmd;

typedef union	u_cmd_info
{
	t_hash_cmd	hash;
	t_se_cmd	se;
}				t_cmd_info;

typedef struct	s_command_line
{
	char					*command_name;
	t_cmd_info				info;
	t_cmd_type				type;
	uint8_t					pad[4];
	const t_cmd_identity	*identity;
}			   t_command_line;

t_command_line	*parse_command_line(int argc, char **argv);

/*
** Parsing Payloads
*/
void			cmd_hash_payload(t_command_line *cmd, int argc, char **argv);
void			cmd_se_payload(t_command_line *cmd, int argc, char **argv);
void			cmd_ae_payload(t_command_line *cmd, int argc, char **argv);


# define MD5_PARSING_FLAGS "pqrs:"
# define MD5_FLAGS "pqrs"
# define SHA256_PARSING_FLAGS "pqrs:"
# define SHA256_FLAGS "pqrs"
# define BASE64_PARSING_FLAGS "dei:o:"
# define BASE64_FLAGS "deio"
# define DES_PARSING_FLAGS "adei:k:o:p:s:v:"
# define DES_FLAGS "adeikopsv"

t_flags			*parse_md5(int argc, char **argv, t_command_line *cmd);
t_flags			*parse_sha256(int argc, char **argv, t_command_line *cmd);
t_flags			*parse_base64(int argc, char **argv, t_command_line *cmd);
t_flags			*parse_des(int argc, char **argv, t_command_line *cmd);
void			print_memory(const void *addr, size_t size);

/*
** Hash functions
*/

// first states already defined in md5_states

enum md5_states {
	A = 0,
	B,
	C,
	D,
};

enum sha256_states {
	E = D + 1,
	F,
	G,
	H,
};

uint32_t	*md5_hash(void *clear, uint64_t len);
uint32_t	*sha256_hash(void *clear, uint64_t len);
uint32_t	*sha224_hash(void *clear, uint64_t len);
uint64_t	*sha512_hash(void *clear, uint64_t len);

/*
** Symmetric encryption functions
*/

# define BASE64_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

uint8_t		*encode_base64(uint8_t *clear, uint64_t len, t_se_key *key);
uint8_t		*decode_base64(uint8_t *cipher, uint64_t len, t_se_key *key);

uint8_t		*encode_des(uint8_t *clear, uint64_t len, t_se_key *key);
uint8_t		*decode_des(uint8_t *cipher, uint64_t len, t_se_key *key);

/*
** Command line execution
*/

NORETURN	exec_cmd(t_command_line *cmd);
void		md5_cmd_exec(t_command_line *cmd);
void		sha256_cmd_exec(t_command_line *cmd);
void		base64_cmd_exec(t_command_line *cmd);
void		des_cmd_exec(t_command_line *cmd);

t_string	read_message_from_stdin(void);
t_string	read_input_file(char *filename);
void		print_hash(uint32_t *digest, uint64_t size, int32_t swap_endian);
void		print_memory(const void *addr, size_t size);

/*
** Hash testers
*/

typedef struct	s_hash_info
{
	t_system_hash_function	system_hash;
	t_hash_function			hash;
	uint64_t				digest_size;
}				t_hash_info;

# define MAX_RANDOM_MESSAGE_LEN 512 * 4 + 11
# define RANDOM_INIT 0xBADA55

int			hash_tester(void *message
					   , uint32_t *to_test_digest
					   , uint64_t len
					   , t_hash_info *hash_info);
NORETURN	hash_fuzzer(t_hash_info *hash_info);

/*
** Useful functions
*/

uint8_t		*str_to_key(char *str);
uint8_t		*bit_permutation(const uint8_t *data
						 , uint32_t size
						 , const uint32_t *permutation_table
						 , uint8_t *output);
uint64_t	bits64_permutation(uint64_t source, uint32_t size, const uint32_t *permutation_table);
uint32_t	bits32_permutation(uint32_t source, uint32_t size, const uint32_t *permutation_table);
/*
** Error handling
*/
void	print_usage(void);

#endif
