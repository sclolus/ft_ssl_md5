/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_md5.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/20 15:21:43 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 02:16:38 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static int32_t	echo_stdin_callback(t_command_line *cmd)
{
	cmd->info.hash.flags.md5.p = 1;
	return (0);
}

static int32_t	quiet_mode_callback(t_command_line *cmd)
{
	cmd->info.hash.flags.md5.q = 1;
	cmd->info.hash.flags.md5.r = 0;
	return (0);
}

static int32_t	reverse_callback(t_command_line *cmd)
{
	if (!cmd->info.hash.flags.md5.q)
		cmd->info.hash.flags.md5.r = 1;
	return (0);
}

static int32_t	given_string_callback(t_command_line *cmd)
{
	cmd->info.hash.flags.md5.s = 1;
	cmd->info.hash.strings_to_hash[cmd->info.hash.nbr_strings] = g_optarg;
	cmd->info.hash.nbr_strings++;
	return (0);
}

t_flags			*parse_md5(int argc, char **argv, t_command_line *cmd)
{
	const static t_parse_callback	callbacks[] = {
		{&echo_stdin_callback, MD5_PARSING_FLAGS[0], {0}},
		{&quiet_mode_callback, MD5_PARSING_FLAGS[1], {0}},
		{&reverse_callback, MD5_PARSING_FLAGS[2], {0}},
		{&given_string_callback, MD5_PARSING_FLAGS[3], {0}},
	};
	char							retrieved_opt;

	ft_bzero(&cmd->info.hash.flags, sizeof(t_flags));
	while ((retrieved_opt = (char)ft_getopt(argc
									, argv, MD5_PARSING_FLAGS)) != -1)
	{
		if (retrieved_opt == GETOPT_ERR_CHAR)
		{
			print_usage();
			_exit(EXIT_FAILURE);
		}
		if (callbacks[(int)(ft_strchr(MD5_FLAGS, retrieved_opt)
							- MD5_FLAGS)].callback(cmd))
			break ;
	}
	cmd->info.hash.filenames = argv + g_optind;
	cmd->info.hash.nbr_files = (uint64_t)argc - (uint64_t)g_optind;
	return (&cmd->info.hash.flags);
}
