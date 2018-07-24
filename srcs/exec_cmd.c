/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   exec_cmd.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sclolus <marvin@42.fr>                     +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/24 22:39:42 by sclolus           #+#    #+#             */
/*   Updated: 2018/07/25 01:05:38 by sclolus          ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl_md5.h"
#include <CommonCrypto/CommonDigest.h>

NORETURN	exec_cmd(t_command_line *cmd)
{
	cmd->hash->cmd_executor(cmd);
	exit(EXIT_SUCCESS);
}
