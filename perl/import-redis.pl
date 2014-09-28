use strict;
use warnings;
use utf8;

use Redis::Fast;
use DBIx::Sunny;

my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
my $port = $ENV{ISU4_DB_PORT} || 3306;
my $username = $ENV{ISU4_DB_USER} || 'root';
my $password = $ENV{ISU4_DB_PASSWORD};
my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

my $db = DBIx::Sunny->connect(
    "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
        RaiseError => 1,
        PrintError => 0,
        AutoInactiveDestroy => 1,
        mysql_enable_utf8   => 1,
        mysql_auto_reconnect => 1,
    },
);


my $redis = Redis::Fast->new;
# all users
for (my $user_id = 1; $user_id <= 200000; $user_id++) {

    my $log = $db->select_row(
        'SELECT COUNT(1) AS failures FROM login_log WHERE user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)',
        $user_id, $user_id);

    $redis->set(sprintf('failure:user:%d', $user_id), $log->{failures});
}

# all ips
my $ips = $db->select_all('SELECT ip FROM login_log GROUP BY ip');
while (my $ip = shift @$ips) {

  my $log = $db->select_row(
    'SELECT COUNT(1) AS failures FROM login_log WHERE ip = ? AND id > IFNULL((select id from login_log where ip = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)',
    $ip, $ip);

  my $failures = $redis->set(sprintf('failure:ip:%s', $ip), $log->{failures});
}





