use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'		=> 'Kismet::Client',
    'VERSION_FROM'	=> 'Client.pm',
    'PREREQ_PM'		=> {
       'Carp' => 0,
       'POSIX' => 0,
       'IO::Select' => 0,
       'IO::Socket' => 0,
       'Socket' => 0,
       'Fcntl' => 0,
    },
    'dist' => { 'COMPRESS' => 'gzip --best' },
   ($] >= 5.005 ?
      (
       AUTHOR     => 'Kay Sindre Bærulfsen <kaysb @ uten.net>') : ()),
);
