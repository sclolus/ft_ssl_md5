/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   exec_cmd.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/24 22:39:42 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 00:29:22 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <CommonCrypto/CommonDigest.h>

static void	hash_strings(t_command_line *cmd)
{
 	uint32_t	i;
	uint32_t	*digest;
	uint64_t	len;

	i = 0;
	while (i < cmd->nbr_strings)
	{
		len = ft_strlen(cmd->strings_to_hash[i]);
		digest = cmd->hash->hash_function(cmd->strings_to_hash[i], len);
		assert(hash_tester(cmd->strings_to_hash[i], digest, len, &(t_hash_info){CC_MD5, md5_hash, 4 * 4}));
		printf("%s (\"%s\") = ", cmd->command_name, cmd->strings_to_hash[i]);
		print_hash(digest, cmd->hash->digest_size);
		printf("\n");
		free(digest);
		i++;
	}
}

static void	hash_file(t_command_line *cmd, char *filename)
{
	uint32_t	*digest;
	t_string	message;

	message = ft_get_file_content(filename);
	if (message.string == NULL)
	{
		ft_error(2, (char*[]){ERR_FILE_OPEN
					, filename}, 0);
		return ;
	}
	digest = cmd->hash->hash_function(message.string, message.len);
	assert(hash_tester(message.string, digest, message.len, &(t_hash_info){cmd->hash->system_hash_function, cmd->hash->hash_function, cmd->hash->digest_size})); //please fix the hashs of directories...
	printf("%s (%s) = ", cmd->command_name, filename);
	print_hash(digest, cmd->hash->digest_size);
	printf("\n");
	free(message.string);
	free(digest);
}

static void	hash_files(t_command_line *cmd)
{
	uint32_t	i;

	i = 0;
	while (i < cmd->nbr_files)
	{
		hash_file(cmd, cmd->filenames[i]);
		i++;
	}
}

NORETURN	exec_cmd(t_command_line *cmd)
{
	hash_strings(cmd);
	hash_files(cmd);
	exit(EXIT_SUCCESS);
}
