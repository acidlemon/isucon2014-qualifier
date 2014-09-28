CREATE TABLE IF NOT EXISTS `users` (
  `id` int NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `login` varchar(255) NOT NULL UNIQUE,
  `password_hash` varchar(255) NOT NULL,
  `salt` varchar(255) NOT NULL,
  INDEX `users_login` (`login`)
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `login_log` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `created_at` datetime NOT NULL,
  `user_id` int,
  `login` varchar(255) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `succeeded` tinyint NOT NULL,
  INDEX `login_log_user_id_succeeded` (`user_id`, `succeeded`),
  INDEX `login_log_ip_succeeded` (`ip`, `succeeded`)
) DEFAULT CHARSET=utf8;
