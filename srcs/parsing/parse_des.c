/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_des.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/26 21:33:13 by sclolus           #+#    #+#             */
/*   Updated: 2018/08/04 11:02:44 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static int32_t	base64_mode_callback(t_command_line *cmd)
{
	cmd->info.se.flags.des.a = 1;
	return (0);
}

static int32_t	decode_mode_callback(t_command_line *cmd)
{
	cmd->info.se.flags.des.d = 1;
	cmd->info.se.flags.des.e = 0;
	return (0);
}

static int32_t	encode_mode_callback(t_command_line *cmd)
{
	cmd->info.se.flags.des.e = 1;
	cmd->info.se.flags.des.d = 0;
	return (0);
}

static int32_t	input_file_callback(t_command_line *cmd)
{
	cmd->info.se.flags.des.i = 1;
	cmd->info.se.input_file = g_optarg;
	return (0);
}
static int32_t	output_file_callback(t_command_line *cmd)
{
	cmd->info.se.flags.des.o = 1;
	cmd->info.se.output_file = g_optarg;
	return (0);
}

static int32_t	key_callback(t_command_line *cmd)
{
	cmd->info.se.flags.des.k = 1;
	cmd->info.se.key = g_optarg;
	return (0);
}

static int32_t	password_callback(t_command_line *cmd)
{
	cmd->info.se.flags.des.p = 1;
	cmd->info.se.password = g_optarg;
	return (0);
}

static int32_t	salt_callback(t_command_line *cmd)
{
	cmd->info.se.flags.des.s = 1;
	cmd->info.se.salt = g_optarg;
	return (0);
}

static int32_t	init_vector_callback(t_command_line *cmd)
{
	cmd->info.se.flags.des.v = 1;
	cmd->info.se.init_vector = g_optarg;
	return (0);
}

t_flags			*parse_des(int argc, char **argv, t_command_line *cmd)
{
	const static t_parse_callback	callbacks[] = {
		{&base64_mode_callback, DES_FLAGS[0], {0}},
		{&decode_mode_callback, DES_FLAGS[1], {0}},
		{&encode_mode_callback, DES_FLAGS[2], {0}},
		{&input_file_callback, DES_FLAGS[3], {0}},
		{&key_callback, DES_FLAGS[4], {0}},
		{&output_file_callback, DES_FLAGS[5], {0}},
		{&password_callback, DES_FLAGS[6], {0}},
		{&salt_callback, DES_FLAGS[7], {0}},
		{&init_vector_callback, DES_FLAGS[8], {0}},
	};
	char							retrieved_opt;

	ft_bzero(&cmd->info.se.flags, sizeof(t_flags));
	cmd->info.se.flags.des.e = 1;
	while ((retrieved_opt = (char)ft_getopt(argc
									, argv, DES_PARSING_FLAGS)) != -1)
	{
		if (retrieved_opt == GETOPT_ERR_CHAR)
		{
			print_usage();
			_exit(EXIT_FAILURE);
		}
		if (callbacks[(int)(ft_strchr(DES_FLAGS, retrieved_opt)
							- DES_FLAGS)].callback(cmd))
			break ;
	}
	/// please insert handling of extra arguments
	return (&cmd->info.se.flags);
}
