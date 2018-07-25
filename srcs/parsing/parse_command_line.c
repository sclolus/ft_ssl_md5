/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_command_line.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/19 15:26:39 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/26 01:02:32 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"

static char				*get_cmd_name(char *command_name)
{
	uint32_t	i;

	i = 0;
	while (i < sizeof(g_supported_cmds) / sizeof(*g_supported_cmds))
	{
		if (!ft_strcmp(command_name, g_supported_cmds[i].name))
			return (g_supported_cmds[i].name);
		i++;
	}
	return (NULL);
}

static t_cmd_type		get_cmd_type(char *command_name)
{
	uint32_t	i;

	i = 0;
	while (i < sizeof(g_supported_cmds) / sizeof(t_hash_identity))
	{
		if (!ft_strcmp(command_name, g_supported_cmds[i].name))
			return (g_supported_cmds[i].type);
		i++;
	}
	return (SUPPORTED_TYPES);
}

/* static void				display_command_line(t_command_line *cmd) */
/* { */
/* 	uint32_t	i; */

/* 	i = 0; */
/* 	if (cmd) */
/* 		return ; */
/* 	printf("name: %s\n", cmd->command_name); */
/* 	while (i < cmd->nbr_strings) */
/* 	{ */
/* 		printf("%u strings_to_hash: %s\n", i, cmd->strings_to_hash[i]); */
/* 		i++; */
/* 	} */
/* 	while (i < cmd->nbr_files) */
/* 	{ */
/* 		printf("%u filenames: %s\n", i, cmd->filenames[i]); */
/* 		i++; */
/* 	} */
/* 	printf("type: %d\n", (int)cmd->type); */
/* 	printf("flags: p: %hhu q: %hhu  r: %hhu s: %hhu\n", cmd->flags.md5.p */
/* 		, cmd->flags.md5.q */
/* 		, cmd->flags.md5.r */
/* 		, cmd->flags.md5.s); */
/* } */

typedef void	(*t_cmd_parse_payloads)(t_command_line *, int, char **);

const static t_cmd_parse_payloads cmd_parse_payloads[SUPPORTED_KINDS] =
{// this structure should be aligned with the definition of enum e_cmd_kind;
	(t_cmd_parse_payloads)&cmd_hash_payload,
	(t_cmd_parse_payloads)&cmd_se_payload,
	(t_cmd_parse_payloads)&cmd_ae_payload,
};

t_command_line			*parse_command_line(int argc, char **argv)
{
	static t_command_line	cmd;
	uint32_t				i;

	ft_bzero(&cmd, sizeof(cmd));
	if (argc < 2)
		return (NULL);
	if (!(cmd.command_name = get_cmd_name(argv[1])))
		ft_error_exit(1, (char*[]){"Unknown command name found"}, EXIT_FAILURE);
// add usage
	cmd.type = get_cmd_type(cmd.command_name);
	i = 0;
	while (i < sizeof(g_supported_cmds) / sizeof(*g_supported_cmds))
	{
		if (g_supported_cmds[i].type == cmd.type)
		{
			cmd_parse_payloads[g_supported_cmds[i].kind](&cmd, argc, argv);
			g_supported_cmds[i].cmd_parse_function((int)argc - 1
													, argv + 1
													, &cmd);
			cmd.identity = (g_supported_cmds + i);
			break ;
		}
		i++;
	}
//	display_command_line(&cmd);
	return (&cmd);
}
