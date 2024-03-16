use spring_security;

create table users (
	username varchar(50) not null primary key,
	password varchar(120) not null,
	enabled boolean not null
);

create table authorities (
    username varchar(50) not null,
    authority varchar(50) not null,
    foreign key (username) references users (username)
);
 
insert into users(username, password, enabled) values('admin','admin',true);
insert into authorities(username,authority) values('admin','ROLE_ADMIN');
insert into users(username, password, enabled) values('employee','employee',true);
insert into authorities(username,authority) values('employee','ROLE_USER');
insert into authorities(username,authority) values('admin','ROLE_USER');