/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_cmd_exec.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/25 01:02:45 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 01:32:52 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <CommonCrypto/CommonDigest.h>

static void	print_string_digest(t_command_line *cmd, char *string, uint32_t *digest)
{
	if (!cmd->flags.md5.q && !cmd->flags.md5.r)
		printf("%s (\"%s\") = ", cmd->command_name, string);
	if (cmd->flags.md5.r)
	{
		print_hash(digest, cmd->hash->digest_size, 1);
		printf(" \"%s\"", string);
	}
	else
	{
		print_hash(digest, cmd->hash->digest_size, 1);
	}
	printf("\n");
}

static void	print_file_digest(t_command_line *cmd, char *name, uint32_t *digest)
{
	if (!cmd->flags.md5.q && !cmd->flags.md5.r)
		printf("%s (%s) = ", cmd->command_name, name);
	if (cmd->flags.md5.r)
	{
		print_hash(digest, cmd->hash->digest_size, 1);
		printf(" %s", name);
	}
	else
	{
		print_hash(digest, cmd->hash->digest_size, 1);
	}
	printf("\n");
}

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
		assert(hash_tester(cmd->strings_to_hash[i], digest, len, &(t_hash_info){cmd->hash->system_hash_function
							   , cmd->hash->hash_function
							   , cmd->hash->digest_size})); //please fix the hashs of directories...
		print_string_digest(cmd, cmd->strings_to_hash[i], digest);
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
	assert(hash_tester(message.string, digest, message.len
					   , &(t_hash_info){cmd->hash->system_hash_function
							   , cmd->hash->hash_function
							   , cmd->hash->digest_size})); //please fix the hashs of directories...
	print_file_digest(cmd, filename, digest);
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

void	md5_cmd_exec(t_command_line *cmd)
{
	hash_strings(cmd);
	hash_files(cmd);
}
