CREATE DATABASE  knockingdb;
USE  knockingdb;

 create table entorno (
identorno int primary key auto_increment,
entorno_name varchar(50),
entorno_code int unique
);

create table proyecto (
idproyecto int primary key auto_increment,
proyecto_name varchar(50),
proyecto_code int unique
);

create table remoto (
idremoto int primary key auto_increment,
remoto_name varchar(50),
remoto_code int unique
);

create table udp (
idudp int primary key auto_increment,
udp_name varchar(50),
udp_ip varchar(50),
udp_puertos varchar(50),
udp_code int unique
);

CREATE TABLE seleccion_check (
    idseleccion INT PRIMARY KEY NOT NULL AUTO_INCREMENT,
    seleccion_dato_remoto INT,
    seleccion_dato_proyecto INT, 
    seleccion_dato_entorno INT,
    seleccion_dato_udp INT,
    webhook VARCHAR(400),
    notificaciones TINYINT,  
    seleccion_code INT UNIQUE,
    seleccionado TINYINT,    
    FOREIGN KEY (seleccion_dato_remoto) REFERENCES remoto(remoto_code),
    FOREIGN KEY (seleccion_dato_proyecto) REFERENCES proyecto(proyecto_code),
    FOREIGN KEY (seleccion_dato_entorno) REFERENCES entorno(entorno_code),
    FOREIGN KEY (seleccion_dato_udp) REFERENCES udp(udp_code)
);

CREATE TABLE solicitud_apertura (
    idsolicitud INT AUTO_INCREMENT PRIMARY KEY,
    solicitud_usuario VARCHAR(50),
    solicitud_remoto INT,
    tipo_opcion VARCHAR(10), -- Tikect o Tarea
    folio VARCHAR(50),
    proyecto_code INT,
    entorno_code INT,
    acceso_bd BOOLEAN,
    acceso_ftp BOOLEAN,
    descripcion TEXT,
    apertura_code INT UNIQUE,
    notificado_expiracion BOOLEAN NOT NULL DEFAULT 0,
    fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE aperturas_iniciadas (
    idapertura INT AUTO_INCREMENT PRIMARY KEY,
    apertura_code INT UNIQUE,
    apertura_tiempo VARCHAR(20) DEFAULT NULL,
    final_time VARCHAR(20),
    descripcion TEXT,
    fecha_apertura DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (apertura_code) REFERENCES solicitud_apertura(apertura_code)
);

CREATE TABLE aperturas_finalizadas (
    idapertura INT AUTO_INCREMENT PRIMARY KEY,
    apertura_code INT,
    apertura_tiempo VARCHAR(20) DEFAULT NULL,
    final_time VARCHAR(20),
    fecha_apertura DATETIME DEFAULT CURRENT_TIMESTAMP,
    descripcion TEXT,
    FOREIGN KEY (apertura_code) REFERENCES solicitud_apertura(apertura_code)
);

CREATE TABLE apertura_imagenes (
    idimagen INT AUTO_INCREMENT PRIMARY KEY,
    apertura_id INT,
    imagen_path TEXT,
    FOREIGN KEY (apertura_id) REFERENCES aperturas_finalizadas(idapertura)
);

CREATE TABLE papelera_imagenes (
    idimagen_papelera INT AUTO_INCREMENT PRIMARY KEY,
    idpapelera INT NOT NULL,
    imagen_path TEXT NOT NULL,
    fecha_eliminacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (idpapelera) REFERENCES papelera(idpapelera) ON DELETE CASCADE
);

CREATE TABLE papelera (
    idpapelera INT AUTO_INCREMENT PRIMARY KEY,
    solicitud_usuario VARCHAR(50),
    solicitud_remoto INT,
    tipo_opcion VARCHAR(10), -- Ticket o Tarea
    folio VARCHAR(50),
    proyecto_code INT,
    entorno_code INT,
    acceso_bd BOOLEAN,
    acceso_ftp BOOLEAN,
    descripcion TEXT,
    apertura_code INT UNIQUE,
    fecha_creacion DATETIME,
    fecha_eliminacion DATETIME DEFAULT CURRENT_TIMESTAMP,
    imagen_paths TEXT
);


CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    acceso_ftp TINYINT,
    remoto_code INT,
    FOREIGN KEY (remoto_code) REFERENCES remoto(remoto_code)
);

INSERT INTO users (username, password, is_admin, remoto_code) VALUES 
('admin', '1234', TRUE, 3001),
('Bryant', '1234', TRUE, 3001),
('usuario', '1234', FALSE, 3002);

CREATE TABLE configuracion (
    id INT PRIMARY KEY AUTO_INCREMENT,
    apertura_libre BOOLEAN DEFAULT FALSE,
    fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webhook_seleccion (
    id INT AUTO_INCREMENT PRIMARY KEY,
    apertura_code INT UNIQUE,
    webhook VARCHAR(400),
    notificaciones TINYINT DEFAULT 1
);

CREATE TABLE logs_sistema (
    idlog INT AUTO_INCREMENT PRIMARY KEY,
    fecha_evento DATETIME DEFAULT CURRENT_TIMESTAMP,
    tipo_evento VARCHAR(50),
    descripcion TEXT,
    usuario VARCHAR(50)
);

CREATE TABLE webhook_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    webhook_url TEXT,
    notificaciones BOOLEAN DEFAULT 1
);



INSERT INTO seleccion_check (
    seleccion_dato_remoto,
    seleccion_dato_proyecto,
    seleccion_dato_entorno,
    seleccion_dato_udp,
    seleccion_code,
    seleccionado
) VALUES (
    3001,  -- remoto_code: Servidor AWS
    2001,  -- proyecto_code: Sistema de Ventas
    1001,  -- entorno_code: Producción
    4001,  -- udp_code: UDP_001
    5001,  -- seleccion_code: código único para esta selección (debes generar uno único)
    1      -- seleccionado (1 = activado, 0 = desactivado)
);



-- Inserciones en la tabla entorno
INSERT INTO entorno (identorno, entorno_name, entorno_code) VALUES
(1, 'Producción', 1001),
(2, 'Desarrollo', 1002),
(3, 'Pruebas', 1003);

-- Inserciones en la tabla proyecto
INSERT INTO proyecto (idproyecto, proyecto_name, proyecto_code) VALUES
(1, 'Sistema de Ventas', 2001),
(2, 'Portal Web', 2002),
(3, 'App Móvil', 2003);

-- Inserciones en la tabla remoto
INSERT INTO remoto (idremoto, remoto_name, remoto_code) VALUES
(1, 'Servidor AWS', 3001),
(2, 'Servidor Azure', 3002),
(3, 'Servidor Local', 3003);

-- Inserciones en la tabla udp con múltiples puertos
INSERT INTO udp (idudp, udp_name, udp_ip, udp_puertos, udp_code) VALUES
(1, 'UDP_001','192.168.2.1', '42010,45010,62500,39050,31938', 4001),
(2, 'UDP_002','000.000.00', '9090,9091,9092', 4002),
(3, 'UDP_003','200.000.0', '7070,7071,7072', 4003);

DELETE FROM udp WHERE idudp = 1;

INSERT INTO udp (idudp, udp_name, udp_ip, udp_puertos, udp_code) VALUES
(1, 'UDP_001','192.168.2.1', '42010,45010,62500,39050,31938', 4001);



-- Inserciones en datos_finales (combinaciones válidas entre los códigos de las otras tablas)
INSERT INTO datos_finales (iddatos_finales, dato_entorno, dato_proyecto, dato_remoto, dato_udp) VALUES
(1, 1001, 2001, 3001, 4001),  -- Producción + Sistema de Ventas + AWS + UDP_001
(2, 1002, 2002, 3002, 4002),  -- Desarrollo + Portal Web + Azure + UDP_002
(3, 1003, 2003, 3003, 4003),  -- Pruebas + App Móvil + Local + UDP_003
(4, 1002, 2001, 3001, 4003),  -- Desarrollo + Ventas + AWS + UDP_003
(5, 1001, 2003, 3002, 4001);  -- Producción + App Móvil + Azure + UDP_001



