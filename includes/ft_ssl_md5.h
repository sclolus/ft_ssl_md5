/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl_md5.h                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/18 01:54:31 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/19 15:53:21 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_MD5
# define FT_SSL_MD5

# include "libft.h"
# include <stdio.h> //
# include <unistd.h>
# include <stdlib.h>
# include <assert.h> //

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
	SUPPORTED_TYPES,
//	SHA224,
	// please add more
}				t_cmd_type;

typedef struct s_hash_identity {
	char		*name;
	t_cmd_type	type;
	uint8_t		pad[4];
}				t_hash_identity;

extern const t_hash_identity	g_supported_hashs[SUPPORTED_TYPES];

/*
** Command line parsing
*/

typedef struct	s_md5_flags
{
	uint8_t	p : 1;
	uint8_t	q : 1;
	uint8_t	r : 1;
	uint8_t	s : 1;
	uint8_t	pad : 4;
}				t_md5_flags;


typedef union	u_flags
{
	t_md5_flags	md5;
}				t_flags;

typedef uint32_t *(*t_hash_function)(void*, uint64_t);

typedef struct	s_command_line
{
	char			*command_name;
	char			**argv;
	uint64_t		argc;
	t_cmd_type		type;
	t_flags			flags;
	uint8_t			pad[3];
	t_hash_function	hash_function;
}			   t_command_line;

t_command_line	*parse_command_line(int argc, char **argv);

void		print_memory(const void *addr, size_t size);

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


/*
** Hash testers
*/

# define MAX_RANDOM_MESSAGE_LEN 512
# define RANDOM_INIT 0xBADA55

typedef unsigned char *(*t_system_hash_function)(const void*, unsigned int, unsigned char*);

int			hash_tester(void *message
					   , uint32_t *to_test_digest
					   , uint64_t len
					   , t_system_hash_function);
NORETURN	hash_fuzzer(t_system_hash_function system_hash, t_hash_function hash_function);

NORETURN	md5_fuzzer(void);
int			md5_tester(void *message, uint32_t *to_test_digest, uint64_t len);


/*
** Error handling
*/
void	print_usage(void);

#endif
