from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask import send_from_directory
from datetime import datetime, timedelta
from datetime import datetime, time
from werkzeug.utils import secure_filename
from contextlib import closing
from datetime import time
from ftplib import FTP, error_perm
from traceback import format_exc
import ctypes
import getpass
import logging
import requests
import mysql.connector
import socket
import threading
import time
import os
import re

app = Flask(__name__)

def get_db():
    return mysql.connector.connect(**db_config)

UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'tu_clave_secreta'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.secret_key = 'tu_clave_secreta'

db_config = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '12345678',
    'database': 'knockingdb'
}


@app.route('/uploads/<path:filename>')
def uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.context_processor
def inject_now():
    return {'now': datetime.now}

# ========== FUNCIONALIDAD: PORT KNOCKING ==========
def hacer_port_knocking(ip, puertos):
    for puerto in puertos:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b'knock', (ip, int(puerto)))
            sock.close()
        except Exception as e:
            print(f"Error al hacer knock en puerto {puerto}: {e}")


# ============================
#     RUTAS DE NAVEGACIÓN
# ============================

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    mensaje = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)

            cursor.execute("SELECT id, username, password, remoto_code, acceso_ftp, is_admin FROM users WHERE username = %s AND password = %s", (username, password))
            user = cursor.fetchone()

            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Error en login: {e}")
            user = None

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['remoto_code'] = user['remoto_code']
            session['acceso_ftp'] = int(user.get('acceso_ftp') or 0)
            session['role'] = 'admin' if user.get('is_admin') == 1 else 'user'
            return redirect(url_for('home'))
        else:
            mensaje = "Credenciales incorrectas"

    return render_template('login.html', mensaje=mensaje)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

def get_db_connection():
    return mysql.connector.connect(**db_config)

def generar_apertura_code():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT MAX(apertura_code) FROM solicitud_apertura")
    resultado = cursor.fetchone()
    conn.close()

    if resultado[0] is None:
        return 1  # Empieze en 01
    else:
        return resultado[0] + 1
    



@app.route('/configuracion/apertura_libre', methods=['POST'])
def cambiar_apertura_libre():
    data = request.get_json()
    nuevo_estado = data.get('apertura_libre', False)

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM configuracion LIMIT 1")
    existe = cursor.fetchone()

    if existe:
        cursor.execute("UPDATE configuracion SET apertura_libre = %s", (nuevo_estado,))
    else:
        cursor.execute("INSERT INTO configuracion (apertura_libre) VALUES (%s)", (nuevo_estado,))
    
    conn.commit()
    cursor.close()
    conn.close()

    # ✔️ Aquí puedes lanzar las notificaciones:
    if nuevo_estado:
        flash('Apertura libre ACTIVADA.', 'success')
        print("Apertura libre ACTIVADA.")
        # enviar_notificacion_discord("⚠️ Apertura libre ACTIVADA.")
        # registrar_log("Apertura libre activada por un usuario.")
    else:
        flash('Apertura libre DESACTIVADA.', 'danger')
        print("Apertura libre DESACTIVADA.")
        # enviar_notificacion_discord("✔️ Apertura libre DESACTIVADA.")
        # registrar_log("Apertura libre desactivada por un usuario.")

    return jsonify({"success": True, "estado": nuevo_estado})


    
@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = session['username']
    role = session.get('role')
    acceso_ftp = int(session.get('acceso_ftp') or 0)
    remoto_nombre = None

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # Obtener acceso_ftp actualizado desde la base de datos
    cursor.execute("SELECT acceso_ftp FROM users WHERE username = %s", (user,))
    acceso_ftp_db = cursor.fetchone()

    if acceso_ftp_db:
        acceso_ftp = int(acceso_ftp_db['acceso_ftp'] or 0)  # Si es None, usa 0
    else:
        acceso_ftp = 0


    # Obtener estado de apertura libre
    cursor.execute("SELECT apertura_libre FROM configuracion LIMIT 1")
    config = cursor.fetchone()
    apertura_libre = config['apertura_libre'] if config else False

    # Verificar si ya tiene una apertura activa (solo importa si apertura libre está apagada)
    cursor.execute("""
        SELECT sa.*, ai.apertura_tiempo, ai.fecha_apertura
        FROM solicitud_apertura sa
        JOIN aperturas_iniciadas ai ON sa.apertura_code = ai.apertura_code
        WHERE sa.solicitud_usuario = %s
        LIMIT 1
    """, (user,))
    ya_tiene_apertura = cursor.fetchone()

    if request.method == 'POST':
        # SOLO BLOQUEA SI apertura_libre es False
        if ya_tiene_apertura and not apertura_libre:
            flash("Ya tienes una apertura activa. No puedes crear otra.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('home'))

        # Obtener datos del formulario
        proyecto = int(request.form.get('proyecto'))
        entorno = int(request.form.get('entorno_select'))
        opcion = request.form.get('opcion')
        folio = request.form.get('dato')
        acceso_bd = bool(request.form.get('caja_opcion1'))
        acceso_ftp = bool(request.form.get('caja_opcion2'))
        descripcion = request.form.get('descripcion')

        # Obtener remoto_code del usuario
        cursor.execute("SELECT remoto_code FROM users WHERE username = %s", (user,))
        user_remoto_info = cursor.fetchone()

        if not user_remoto_info or user_remoto_info['remoto_code'] is None:
            flash("Tu usuario no tiene un servidor remoto asignado. Contacta al administrador.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('home'))

        usuario_remoto_code = user_remoto_info['remoto_code']

        # Verificar si hay un acceso activo
        cursor.execute("""
            SELECT sc.*, r.remoto_name, udp.udp_ip, udp.udp_puertos
            FROM seleccion_check sc
            JOIN remoto r ON sc.seleccion_dato_remoto = r.remoto_code
            JOIN udp ON sc.seleccion_dato_udp = udp.udp_code
            WHERE sc.seleccionado = 1
              AND sc.seleccion_dato_proyecto = %s
              AND sc.seleccion_dato_entorno = %s
              AND sc.seleccion_dato_remoto = %s
            LIMIT 1
        """, (proyecto, entorno, usuario_remoto_code))

        seleccion = cursor.fetchone()

        if not seleccion:
            flash("No hay un acceso activo configurado. Contacta al administrador.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('home'))

        remoto_code = seleccion['seleccion_dato_remoto']
        remoto_nombre = seleccion['remoto_name']
        puertos = seleccion['udp_puertos'].split(',')
        ip = seleccion['udp_ip']

        # Crear nuevo código de apertura
        cursor.execute("SELECT MAX(apertura_code) AS max_code FROM solicitud_apertura")
        max_code = cursor.fetchone()['max_code'] or 0
        apertura_code = max_code + 1

        # Insertar solicitud
        cursor.execute("""
            INSERT INTO solicitud_apertura (
                solicitud_usuario, solicitud_remoto, tipo_opcion, folio,
                proyecto_code, entorno_code, acceso_bd, acceso_ftp,
                descripcion, apertura_code
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user, remoto_code, opcion, folio, proyecto, entorno,
            acceso_bd, acceso_ftp, descripcion, apertura_code
        ))

        now = datetime.now()
        duracion_minutos = 1 # Tiempo de la apertura en minutos
        tiempo_limite_str = f"{duracion_minutos // 60:02d}:{duracion_minutos % 60:02d}:00"

        # Port Knocking
        hacer_port_knocking(ip, puertos)

        # Obtener nombres
        cursor.execute("SELECT proyecto_name FROM proyecto WHERE proyecto_code = %s", (proyecto,))
        proyecto_nombre = cursor.fetchone()['proyecto_name']

        cursor.execute("SELECT entorno_name FROM entorno WHERE entorno_code = %s", (entorno,))
        entorno_nombre = cursor.fetchone()['entorno_name']

        # Enviar notificación
        webhooks_utilizados = enviar_notificacion_discord(
            user, proyecto_nombre, entorno_nombre, duracion_minutos,
            acceso_bd=acceso_bd, acceso_ftp=acceso_ftp,
            folio=folio, apertura_code=apertura_code,
            tipo_opcion=opcion
        )

        # Esto funcionará bien aunque sea una lista vacía
        for webhook_url in webhooks_utilizados:
            guardar_webhook_apertura(apertura_code, webhook_url)

        session['webhooks_notificacion'] = webhooks_utilizados
        session.modified = True


        # Insertar apertura iniciada
        cursor.execute("""
            INSERT INTO aperturas_iniciadas (apertura_code, apertura_tiempo, fecha_apertura)
            VALUES (%s, %s, %s)
        """, (apertura_code, tiempo_limite_str, now))

        # Registrar log de apertura
        evento = f"Apertura de Puertos"
        descripcion_log = f"Apertura iniciada por {user} en entorno '{entorno_nombre}' del proyecto '{proyecto_nombre}' con código #{apertura_code}"
        registrar_log(evento, descripcion_log, user)

        conn.commit()
        cursor.close()
        conn.close()

        flash("Apertura iniciada correctamente.", "success")
        return redirect(url_for('apertura', code=apertura_code))

    # GET: cargar listas
    cursor.execute("SELECT * FROM proyecto")
    proyectos = cursor.fetchall()

    cursor.execute("SELECT * FROM entorno")
    entornos = cursor.fetchall()

    cursor.execute("""
        SELECT r.remoto_name
        FROM users u
        LEFT JOIN remoto r ON u.remoto_code = r.remoto_code
        WHERE u.username = %s
    """, (user,))
    remoto_result = cursor.fetchone()
    remoto_nombre = remoto_result['remoto_name'] if remoto_result else "No asignado"

    cursor.close()
    conn.close()

    # Procesos en background
    threading.Thread(target=mover_a_finalizadas).start()

    return render_template("home.html",
                           proyectos=proyectos,
                           entornos=entornos,
                           remoto_nombre=remoto_nombre,
                           user=user,
                           role=role,
                           acceso_ftp=acceso_ftp,
                           solicitud=ya_tiene_apertura,
                           apertura_libre=apertura_libre)



#####################################################################################################################################################################
## Apertura
#####################################################################################################################################################################
@app.route('/apertura')
def apertura():
    if 'username' not in session:
        return redirect(url_for('login'))

    usuario = session['username']
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT sa.*, ai.apertura_tiempo, ai.fecha_apertura, 
               r.remoto_name AS remoto_nombre, 
               p.proyecto_name AS proyecto_name, 
               e.entorno_name AS entorno_name
        FROM solicitud_apertura sa
        JOIN aperturas_iniciadas ai ON sa.apertura_code = ai.apertura_code
        JOIN remoto r ON r.remoto_code = sa.solicitud_remoto
        JOIN proyecto p ON p.proyecto_code = sa.proyecto_code
        JOIN entorno e ON e.entorno_code = sa.entorno_code
        WHERE sa.solicitud_usuario = %s
        ORDER BY ai.fecha_apertura DESC
    """, (usuario,))
    solicitudes = cursor.fetchall()

    cursor.close()
    conn.close()

    if not solicitudes:
        flash("No tienes aperturas activas actualmente.", "warning")
        return redirect(url_for('home'))

    # Separar la primera solicitud y las demás
    primera_solicitud = solicitudes[0]
    solicitudes_restantes = solicitudes[1:] if len(solicitudes) > 1 else []

    return render_template('solicitud_en_curso.html',
                           user=usuario,
                           role=session.get('role'),
                           acceso_ftp=session.get('acceso_ftp'),
                           solicitud=primera_solicitud,
                           solicitudes_restantes=solicitudes_restantes,
                           remoto_nombre=primera_solicitud['remoto_nombre'])


@app.route('/iniciar_apertura', methods=['POST'])
def iniciar_apertura():
    if 'username' not in session:
        return jsonify({"error": "No autenticado"}), 401

    apertura_code = request.form.get('apertura_code')
    tiempo_inicial = request.form.get('tiempo_inicial')

    if not apertura_code or not tiempo_inicial:
        return jsonify({"error": "Faltan datos"}), 400

    import re
    if not re.match(r'^\d{2}:\d{2}:\d{2}$', tiempo_inicial):
        return jsonify({"error": "Formato de tiempo no válido"}), 400

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO aperturas_iniciadas (apertura_code, apertura_tiempo, final_time)
            VALUES (%s, %s, %s)
        """, (apertura_code, tiempo_inicial, tiempo_inicial))
        conn.commit()

        # Registra log
        descripcion_log = f"Se inició apertura con código {apertura_code}, tiempo configurado {tiempo_inicial}."
        registrar_log(
            tipo_evento="Apertura de Puertos",
            descripcion=descripcion_log,
            usuario=session['username']
        )

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

    return jsonify({"success": True})



@app.route('/actualizar_tiempo_apertura', methods=['POST'])
def actualizar_tiempo_apertura():
    if 'username' not in session:
        return jsonify({"error": "No autenticado"}), 401

    data = request.get_json()
    apertura_code = data.get('apertura_code')
    tiempo_restante = data.get('tiempo_restante', '')  # Formato HH:MM:SS

    # Validación del formato de tiempo
    if not re.match(r'^\d{2}:\d{2}:\d{2}$', tiempo_restante):
        return jsonify({"error": "Formato de tiempo no válido"}), 400

    if tiempo_restante == "00:00:00":
        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # Consultar datos y el estado de notificación
        cursor.execute("""
            SELECT sa.solicitud_usuario, sa.folio, sa.tipo_opcion,
                   sa.acceso_bd, sa.acceso_ftp,
                   p.proyecto_name, e.entorno_name,
                   sa.notificado_expiracion
            FROM solicitud_apertura sa
            JOIN proyecto p ON sa.proyecto_code = p.proyecto_code
            JOIN entorno e ON sa.entorno_code = e.entorno_code
            WHERE sa.apertura_code = %s
            LIMIT 1
        """, (apertura_code,))
        datos = cursor.fetchone()

        if not datos:
            cursor.close()
            conn.close()
            return jsonify({"error": "Apertura no encontrada"}), 404

        # Solo notificar si no se ha notificado antes
        if not datos['notificado_expiracion']:
            exito = notificar_expiracion(
                apertura_code=apertura_code,
                usuario=datos['solicitud_usuario'],
                proyecto=datos['proyecto_name'],
                entorno=datos['entorno_name'],
                folio=datos['folio'],
                tipo_opcion=datos['tipo_opcion'],
                acceso_bd=datos['acceso_bd'],
                acceso_ftp=datos['acceso_ftp'],
                tiempo_asignado="00:00:00"
            )

            # Actualizar que ya se notificó
            cursor.execute("""
                UPDATE solicitud_apertura SET notificado_expiracion = 1
                WHERE apertura_code = %s
            """, (apertura_code,))
            conn.commit()
        else:
            exito = False  # Ya fue notificado antes

        cursor.close()
        conn.close()

        return jsonify({
            "expired": True,
            "notificado": exito,
            "message": "El tiempo de apertura ha expirado" + (" y se notificó al webhook" if exito else " (ya notificado antes)")
        }), 200

    # Si no ha expirado
    return jsonify({"success": True, "message": "Tiempo actualizado"}), 200




# Ruta: /finalizar_apertura
@app.route('/finalizar_apertura', methods=['POST'])
def finalizar_apertura():
    if 'username' not in session:
        return redirect(url_for('login'))

    usuario = session['username']
    apertura_code = request.form.get('apertura_code')

    if not apertura_code:
        flash("Código de apertura faltante.", "danger")
        return redirect(url_for('apertura'))

    conexion = mysql.connector.connect(**db_config)
    cursor = conexion.cursor(dictionary=True)

    cursor.execute("""
        SELECT ai.*, 
        sa.descripcion AS desc_solicitud, 
        sa.proyecto_code, sa.entorno_code, 
        sa.acceso_bd, sa.acceso_ftp,
        sa.tipo_opcion, sa.folio, sa.apertura_code
        FROM aperturas_iniciadas ai
        JOIN solicitud_apertura sa ON ai.apertura_code = sa.apertura_code
        WHERE ai.apertura_code = %s AND sa.solicitud_usuario = %s
        LIMIT 1
    """, (apertura_code, usuario))
    apertura = cursor.fetchone()

    if not apertura:
        flash("No se encontró una apertura activa válida.", "warning")
        return redirect(url_for('apertura'))

    from datetime import datetime
    fecha_inicio = apertura['fecha_apertura']
    fecha_final = datetime.now()
    tiempo_resolucion = str(fecha_final - fecha_inicio).split('.')[0]

    descripcion = (request.form.getlist('descripcion[]')[0] or apertura['desc_solicitud']).strip()

    cursor.execute("""
        INSERT INTO aperturas_finalizadas (
            apertura_code, apertura_tiempo, fecha_apertura, descripcion, final_time
        ) VALUES (%s, %s, %s, %s, %s)
    """, (
        apertura['apertura_code'],
        apertura['apertura_tiempo'],
        apertura['fecha_apertura'],
        descripcion,
        tiempo_resolucion
    ))
    apertura_finalizada_id = cursor.lastrowid

    imagenes = request.files.getlist('imagen[]')
    for img in imagenes:
        if img and img.filename != '' and allowed_file(img.filename):
            filename = secure_filename(img.filename)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
            nombre_unico = f"{timestamp}_{filename}"

            filepath = os.path.join(app.config['UPLOAD_FOLDER'], nombre_unico)
            img.save(filepath)

            cursor.execute("""
                INSERT INTO apertura_imagenes (apertura_id, imagen_path)
                VALUES (%s, %s)
            """, (apertura_finalizada_id, nombre_unico))

    cursor.execute("DELETE FROM aperturas_iniciadas WHERE apertura_code = %s", (apertura_code,))

    cursor.execute("SELECT proyecto_name FROM proyecto WHERE proyecto_code = %s", (apertura['proyecto_code'],))
    proyecto_nombre = cursor.fetchone()['proyecto_name']

    cursor.execute("SELECT entorno_name FROM entorno WHERE entorno_code = %s", (apertura['entorno_code'],))
    entorno_nombre = cursor.fetchone()['entorno_name']

    webhooks = session.get('webhooks_notificacion', [])

    notificar_finalizacion(
        apertura_code=apertura_code,
        usuario=usuario,
        proyecto=proyecto_nombre,
        entorno=entorno_nombre,
        acceso_bd=apertura.get('acceso_bd', False),
        acceso_ftp=apertura.get('acceso_ftp', False),
        folio=apertura.get('folio'),
        tipo_opcion=apertura.get('tipo_opcion'),
        tiempo_resolucion=tiempo_resolucion
    )

    # ✅ REGISTRAR LOG
    mensaje_log = (
        f"Finalizó apertura #{apertura_code} | Proyecto: {proyecto_nombre}, "
        f"Entorno: {entorno_nombre}, Tiempo: {tiempo_resolucion}"
    )
    registrar_log("Cierre de Apertura", mensaje_log, usuario)

    conexion.commit()
    cursor.close()
    conexion.close()

    flash("Acceso finalizado. Conexión cerrada y datos guardados correctamente.", "success")
    return redirect(url_for('apertura'))



def mover_a_finalizadas():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    now = datetime.now()

    cursor.execute("SELECT * FROM aperturas_iniciadas")
    iniciadas = cursor.fetchall()

    for apertura in iniciadas:
        # fecha_apertura es datetime, apertura_tiempo es time → combínalos
        fecha = apertura['fecha_apertura']
        tiempo = apertura['apertura_tiempo']

        # Combinar fecha y hora en un datetime
        tiempo_limite = datetime.combine(fecha.date(), tiempo)

        if now > tiempo_limite:
            # Mover a finalizadas
            cursor.execute("""
                INSERT INTO aperturas_finalizadas (apertura_code, apertura_tiempo, fecha_apertura)
                VALUES (%s, %s, %s)
            """, (apertura['apertura_code'], tiempo, fecha))

            # Eliminar de iniciadas
            cursor.execute("DELETE FROM aperturas_iniciadas WHERE apertura_code = %s", (apertura['apertura_code'],))

    conn.commit()
    cursor.close()
    conn.close()


def parse_fecha(fecha_str):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(fecha_str, fmt)
        except ValueError:
            continue
    return None


#####################################################################################################################################################################
## Actividades
#####################################################################################################################################################################

@app.route('/actividades')
def actividades():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT ai.*, 
               sa.solicitud_usuario, sa.folio, sa.tipo_opcion,
               sa.acceso_bd, sa.acceso_ftp, sa.descripcion,
               sa.proyecto_code, sa.entorno_code,
               sa.notificado_expiracion,  -- aquí se verifica
               p.proyecto_name, e.entorno_name, r.remoto_name
        FROM aperturas_iniciadas ai
        JOIN solicitud_apertura sa ON ai.apertura_code = sa.apertura_code
        LEFT JOIN proyecto p ON sa.proyecto_code = p.proyecto_code
        LEFT JOIN entorno e ON sa.entorno_code = e.entorno_code
        LEFT JOIN remoto r ON sa.solicitud_remoto = r.remoto_code
        ORDER BY ai.fecha_apertura DESC
    """)

    actividades = cursor.fetchall()

    for act in actividades:
        apertura_code = act['apertura_code']
        usuario = act['solicitud_usuario']
        proyecto = act['proyecto_name'] or "Desconocido"
        entorno = act['entorno_name'] or "Desconocido"
        folio = act['folio']
        tipo_opcion = act['tipo_opcion']
        acceso_bd = act['acceso_bd']
        acceso_ftp = act['acceso_ftp']
        apertura_tiempo = act['apertura_tiempo']
        fecha_apertura = act['fecha_apertura']
        notificado = act.get('notificado_expiracion', False)

        # Parseo de tiempo y fecha
        if isinstance(apertura_tiempo, str):
            try:
                apertura_tiempo = datetime.strptime(apertura_tiempo, "%H:%M:%S.%f").time()
            except ValueError:
                apertura_tiempo = datetime.strptime(apertura_tiempo, "%H:%M:%S").time()

        if isinstance(fecha_apertura, str):
            try:
                fecha_apertura = datetime.strptime(fecha_apertura, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                fecha_apertura = datetime.strptime(fecha_apertura, "%Y-%m-%d %H:%M:%S")

        # Calcular expiración
        expiracion = fecha_apertura + timedelta(
            hours=apertura_tiempo.hour,
            minutes=apertura_tiempo.minute,
            seconds=apertura_tiempo.second
        )

        ahora = datetime.now()

        if ahora > expiracion or apertura_tiempo.strftime("%H:%M:%S") == "00:00:00":
            act['estado'] = 'expirada'

            if not notificado:
                # Solo notificar si no ha sido notificado antes
                tiempo_asignado = apertura_tiempo.strftime("%H:%M:%S")
                exito = notificar_expiracion(
                    apertura_code=apertura_code,
                    usuario=usuario,
                    proyecto=proyecto,
                    entorno=entorno,
                    folio=folio,
                    tipo_opcion=tipo_opcion,
                    acceso_bd=acceso_bd,
                    acceso_ftp=acceso_ftp,
                    tiempo_asignado=tiempo_asignado
                )

                if exito:
                    # Actualizar el campo notificado_expiracion en solicitud_apertura
                    update_cursor = conn.cursor()
                    update_cursor.execute("""
                        UPDATE solicitud_apertura
                        SET notificado_expiracion = TRUE
                        WHERE apertura_code = %s
                    """, (apertura_code,))
                    conn.commit()
                    update_cursor.close()
                    print(f"✅ Notificación enviada y marcada como enviada para #{apertura_code}")
                else:
                    print(f"⚠️ Error al notificar expiración para #{apertura_code}")
        else:
            act['estado'] = 'activa'

        act['apertura_tiempo_str'] = apertura_tiempo.strftime("%H:%M:%S")
        act['fecha_apertura_str'] = fecha_apertura.strftime("%d/%m/%Y %H:%M:%S")

    cursor.close()
    conn.close()

    return render_template(
        "actividades.html",
        user=session.get('username'),
        role=session.get('role'),
        acceso_ftp=session.get('acceso_ftp'),
        actividades=actividades
    )





#####################################################################################################################################################################
## Solicitudes
#####################################################################################################################################################################

@app.route('/solicitudes')
def solicitudes():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = session['username']
    role = session.get('role', 'user')

    with closing(get_db()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
        aperturas = []

        query_finalizadas = """
            SELECT f.idapertura, f.apertura_code, f.apertura_tiempo, f.final_time, f.fecha_apertura, f.descripcion,
                   s.solicitud_usuario, s.tipo_opcion, s.folio,
                   s.proyecto_code, s.entorno_code, s.descripcion AS descripcion_apertura,
                   s.acceso_bd, s.acceso_ftp, 
                   p.proyecto_name, e.entorno_name
            FROM aperturas_finalizadas f
            JOIN solicitud_apertura s ON f.apertura_code = s.apertura_code
            JOIN proyecto p ON s.proyecto_code = p.proyecto_code
            JOIN entorno e ON s.entorno_code = e.entorno_code
        """
        if role != 'admin':
            query_finalizadas += " WHERE s.solicitud_usuario = %s"
            query_finalizadas += " ORDER BY f.fecha_apertura DESC"
            cursor.execute(query_finalizadas, (user,))
        else:
            query_finalizadas += " ORDER BY f.fecha_apertura DESC"
            cursor.execute(query_finalizadas)

        aperturas = cursor.fetchall()

        # Convertir fecha_apertura a datetime si viene como string
        for a in aperturas:
            if isinstance(a['fecha_apertura'], str):
                a['fecha_apertura'] = parse_fecha(a['fecha_apertura'])

        # Obtener imágenes relacionadas
        idaperturas = [a['idapertura'] for a in aperturas]
        imagenes_dict = {}
        if idaperturas:
            format_strings = ','.join(['%s'] * len(idaperturas))
            cursor.execute(f"""
                SELECT apertura_id, imagen_path
                FROM apertura_imagenes
                WHERE apertura_id IN ({format_strings})
            """, idaperturas)
            imagenes = cursor.fetchall()
            for img in imagenes:
                key = img['apertura_id']
                if key not in imagenes_dict:
                    imagenes_dict[key] = []
                imagenes_dict[key].append(img['imagen_path'])
        for a in aperturas:
            a['imagenes'] = imagenes_dict.get(a['idapertura'], [])

    return render_template(
        'solicitudes.html',
        acceso_ftp=session.get('acceso_ftp'),
        user=user,
        role=role,
        aperturas=aperturas,
        vista='finalizadas',
        total_pendientes=0
    )


#####################################################################################################################################################################
## Usuarios
#####################################################################################################################################################################


@app.route('/usuarios')
def usuarios():
    if session.get('role') != 'admin':
        flash('No tienes permiso para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Obtener usuarios con nombre del servidor remoto
        cursor.execute("""
            SELECT 
                u.id, u.username, u.password, 
                CASE WHEN u.is_admin = 1 THEN 'admin' ELSE 'usuario' END AS rol,
                r.remoto_name,
                u.acceso_ftp
            FROM users u
            LEFT JOIN remoto r ON u.remoto_code = r.remoto_code
        """)
        usuarios = cursor.fetchall()

        # Obtener lista de servidores remotos para el formulario
        cursor.execute("SELECT remoto_code, remoto_name FROM remoto")
        remotos = cursor.fetchall()

        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Error en /usuarios: {e}")
        usuarios = []
        remotos = []

    return render_template(
        'usuarios.html',
        user=session.get('username'),
        role=session.get('role'),
        acceso_ftp=session.get('acceso_ftp'),
        usuarios=usuarios,
        remotos=remotos,
        active_tab='usuarios'
    )

@app.route('/usuarios/toggle_ftp', methods=['POST'])
def toggle_ftp():
    if session.get('role') != 'admin':
        flash('No tienes permiso para realizar esta acción.', 'danger')
        return jsonify({'error': 'Acceso denegado'}), 403

    data = request.get_json()
    user_id = data.get('id')
    acceso_ftp = data.get('acceso_ftp', 0)

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Obtener el username del usuario para el mensaje
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        # Actualizar acceso_ftp
        cursor.execute("UPDATE users SET acceso_ftp = %s WHERE id = %s", (acceso_ftp, user_id))
        conn.commit()

        cursor.close()
        conn.close()

        # Mensaje flash dinámico según el estado
        if acceso_ftp == 1:
            flash(f"Se activó el acceso FTP para el usuario {user['username']}.", "success")
        else:
            flash(f"Se desactivó el acceso FTP para el usuario {user['username']}.", "warning")

        return jsonify({'message': 'Actualizado correctamente'})
    except Exception as e:
        print(f"Error al actualizar acceso_ftp: {e}")
        return jsonify({'error': 'Error en el servidor'}), 500


@app.route('/usuarios/agregar', methods=['POST'])
def agregar_usuario():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    username = request.form['username']
    password = request.form['password']
    is_admin = bool(int(request.form.get('is_admin', 0)))
    remoto_code = request.form.get('remoto_code') or None

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, is_admin, remoto_code) VALUES (%s, %s, %s, %s)",
            (username, password, is_admin, remoto_code)
        )
        conn.commit()
        cursor.close()
        conn.close()
        flash(f'Usuario "{username}" agregado correctamente.', 'success')
    except Exception as e:
        flash(f'Error al agregar usuario "{username}": {e}', 'danger')
        print(f"Error agregando usuario: {e}")

    return redirect(url_for('usuarios'))


@app.route('/usuarios/editar/<int:id>', methods=['POST'])
def editar_usuario(id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    username = request.form['username']
    password = request.form['password']
    is_admin = bool(int(request.form.get('is_admin', 0)))
    remoto_code = request.form.get('remoto_code') or None

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET username=%s, password=%s, is_admin=%s, remoto_code=%s WHERE id=%s
        """, (username, password, is_admin, remoto_code, id))
        conn.commit()
        cursor.close()
        conn.close()
        flash(f'Usuario "{username}" editado correctamente.', 'success')
    except Exception as e:
        flash(f'Error al editar usuario "{username}": {e}', 'danger')
        print(f"Error editando usuario: {e}")

    return redirect(url_for('usuarios'))


@app.route('/usuarios/eliminar/<int:user_id>', methods=['GET'])
def eliminar_usuario(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    try:
        # Obtener username para mostrar en el mensaje
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        usuario = cursor.fetchone()
        username = usuario['username'] if usuario else 'desconocido'

        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash(f'Usuario "{username}" eliminado correctamente.', 'success')
    except Exception as e:
        flash(f'Error al eliminar usuario: {e}', 'danger')
        print(f"Error al eliminar usuario: {e}")

    return redirect(url_for('usuarios'))



#####################################################################################################################################################################
## Puertos UDP
#####################################################################################################################################################################


@app.route('/puertosUDP')
def puertosUDP():
    if session.get('role') != 'admin':
        flash('No tienes permiso para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))
    with closing(get_db()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM udp ORDER BY idudp")
        udps = cursor.fetchall()
    return render_template('puertosUDP.html', udps=udps, acceso_ftp=session.get('acceso_ftp'), user=session.get('username'), role=session.get('role'))

@app.route('/udp/agregar', methods=['POST'])
def agregar_udp():
    if session.get('role') != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('puertosUDP'))

    udp_name = request.form['udp_name'].strip()
    udp_ip = request.form['udp_ip'].strip()
    udp_puertos = request.form['udp_puertos'].strip()
    # Ya no se recibirá udp_code desde el formulario, se calculará automático.

    if not (udp_name and udp_ip and udp_puertos):
        flash('Todos los campos son obligatorios', 'warning')
        return redirect(url_for('puertosUDP'))

    try:
        with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
            # Obtener el udp_code máximo actual (o 4000 si no hay ninguno)
            cursor.execute("SELECT IFNULL(MAX(udp_code), 4000) FROM udp")
            max_code = cursor.fetchone()[0]
            nuevo_code = max_code + 1

            cursor.execute("""
                INSERT INTO udp (udp_name, udp_ip, udp_puertos, udp_code)
                VALUES (%s, %s, %s, %s)
            """, (udp_name, udp_ip, udp_puertos, nuevo_code))
            conn.commit()
        flash(f'Puerto UDP "{udp_name}" agregado correctamente.', 'success')
    except mysql.connector.Error as e:
        flash(f'Error al agregar puerto UDP: {e}', 'danger')

    return redirect(url_for('puertosUDP'))

@app.route('/udp/editar/<int:idudp>', methods=['POST'])
def editar_udp(idudp):
    if session.get('role') != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('puertosUDP'))

    udp_name = request.form['udp_name'].strip()
    udp_ip = request.form['udp_ip'].strip()
    udp_puertos = request.form['udp_puertos'].strip()

    if not (udp_name and udp_ip and udp_puertos):
        flash('Todos los campos son obligatorios', 'warning')
        return redirect(url_for('puertosUDP'))

    try:
        with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
            cursor.execute("""
                UPDATE udp SET udp_name=%s, udp_ip=%s, udp_puertos=%s WHERE idudp=%s
            """, (udp_name, udp_ip, udp_puertos, idudp))
            conn.commit()
        flash(f'Puerto UDP "{udp_name}" actualizado correctamente.', 'success')
    except mysql.connector.Error as e:
        flash(f'Error al actualizar puerto UDP: {e}', 'danger')

    return redirect(url_for('puertosUDP'))


@app.route('/udp/eliminar/<int:idudp>', methods=['POST'])
def eliminar_udp(idudp):
    if session.get('role') != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('puertosUDP'))
    try:
        with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
            cursor.execute("DELETE FROM udp WHERE idudp=%s", (idudp,))
            conn.commit()
        flash('Puerto UDP eliminado correctamente.', 'success')
    except mysql.connector.Error as e:
        flash(f'Error al eliminar puerto UDP: {e}', 'danger')

    return redirect(url_for('puertosUDP'))


#####################################################################################################################################################################
## Servidores remotos
#####################################################################################################################################################################

@app.route('/remotos')
def remotos():
    if session.get('role') != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('home'))
    with closing(get_db()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM remoto ORDER BY idremoto")
        remotos = cursor.fetchall()
    return render_template('remotos.html', remotos=remotos, acceso_ftp=session.get('acceso_ftp'), user=session.get('username'), role=session.get('role'))

@app.route('/remoto/agregar', methods=['POST'])
def agregar_remoto():
    if session.get('role') != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('remotos'))
    
    remoto_name = request.form['remoto_name'].strip()

    if not remoto_name:
        flash('El nombre del remoto es obligatorio.', 'warning')
        return redirect(url_for('remotos'))

    try:
        with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
            # Asignar remoto_code automáticamente
            cursor.execute("SELECT IFNULL(MAX(remoto_code), 5000) FROM remoto")
            max_code = cursor.fetchone()[0]
            nuevo_code = max_code + 1

            cursor.execute("INSERT INTO remoto (remoto_name, remoto_code) VALUES (%s, %s)", (remoto_name, nuevo_code))
            conn.commit()
        flash(f'Remoto "{remoto_name}" agregado correctamente.', 'success')
    except mysql.connector.Error as e:
        flash(f'Error al agregar remoto: {e}', 'danger')
    
    return redirect(url_for('remotos'))

@app.route('/remoto/editar/<int:idremoto>', methods=['POST'])
def editar_remoto(idremoto):
    if session.get('role') != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('remotos'))

    remoto_name = request.form['remoto_name'].strip()
    if not remoto_name:
        flash('El nombre del remoto es obligatorio.', 'warning')
        return redirect(url_for('remotos'))

    try:
        with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
            cursor.execute("UPDATE remoto SET remoto_name=%s WHERE idremoto=%s", (remoto_name, idremoto))
            conn.commit()
        flash(f'Remoto "{remoto_name}" actualizado correctamente.', 'success')
    except mysql.connector.Error as e:
        flash(f'Error al actualizar remoto: {e}', 'danger')

    return redirect(url_for('remotos'))

@app.route('/remoto/eliminar/<int:idremoto>', methods=['POST'])
def eliminar_remoto(idremoto):
    if session.get('role') != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('remotos'))

    try:
        with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
            cursor.execute("DELETE FROM remoto WHERE idremoto=%s", (idremoto,))
            conn.commit()
        flash('Remoto eliminado correctamente.', 'success')
    except mysql.connector.Error as e:
        flash(f'Error al eliminar remoto: {e}', 'danger')

    return redirect(url_for('remotos'))



#####################################################################################################################################################################
## Proyectos
#####################################################################################################################################################################

@app.route('/proyectos')
def proyectos():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('login'))

    with closing(get_db()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM proyecto ORDER BY idproyecto ASC")
        proyectos = cursor.fetchall()

    return render_template('proyectos.html', proyectos=proyectos, acceso_ftp=session.get('acceso_ftp'), user=session['username'], role=session['role'])


@app.route('/proyecto/agregar', methods=['POST'])
def agregar_proyecto():
    name = request.form['proyecto_name']
    with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
        cursor.execute("SELECT IFNULL(MAX(proyecto_code), 2000) FROM proyecto")
        max_code = cursor.fetchone()[0]
        new_code = max_code + 1

        cursor.execute("INSERT INTO proyecto (proyecto_name, proyecto_code) VALUES (%s, %s)", (name, new_code))
        conn.commit()
    flash("Proyecto agregado correctamente", "success")
    return redirect(url_for('proyectos'))


@app.route('/proyecto/editar/<int:id>', methods=['POST'])
def editar_proyecto(id):
    name = request.form['proyecto_name']
    with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
        cursor.execute("UPDATE proyecto SET proyecto_name=%s WHERE idproyecto=%s", (name, id))
        conn.commit()
    flash("Proyecto actualizado correctamente", "success")
    return redirect(url_for('proyectos'))


@app.route('/proyecto/eliminar/<int:id>', methods=['POST'])
def eliminar_proyecto(id):
    with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
        cursor.execute("DELETE FROM proyecto WHERE idproyecto=%s", (id,))
        conn.commit()
    flash("Proyecto eliminado correctamente", "success")
    return redirect(url_for('proyectos'))



#####################################################################################################################################################################
## Entornos
#####################################################################################################################################################################


@app.route('/entornos')
def entornos():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('login'))

    with closing(get_db()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM entorno ORDER BY identorno ASC")
        entornos = cursor.fetchall()

    return render_template('entornos.html', entornos=entornos, acceso_ftp=session.get('acceso_ftp'), user=session['username'], role=session['role'])

# Agregar entorno
@app.route('/entornos/agregar', methods=['POST'])
def agregar_entorno():
    nombre = request.form['entorno_name'].strip()

    if not nombre:
        flash('El nombre es obligatorio.', 'warning')
        return redirect(url_for('entornos'))

    try:
        with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
            cursor.execute("SELECT IFNULL(MAX(entorno_code), 2000) FROM entorno")
            max_code = cursor.fetchone()[0]
            nuevo_code = max_code + 1

            cursor.execute("INSERT INTO entorno (entorno_name, entorno_code) VALUES (%s, %s)", (nombre, nuevo_code))
            conn.commit()
        flash(f'Entorno "{nombre}" agregado correctamente.', 'success')
    except Exception as e:
        flash(f'Error al agregar entorno: {e}', 'danger')

    return redirect(url_for('entornos'))

# Editar entorno
@app.route('/entornos/editar/<int:identorno>', methods=['POST'])
def editar_entorno(identorno):
    nombre = request.form['entorno_name'].strip()

    if not nombre:
        flash('El nombre es obligatorio.', 'warning')
        return redirect(url_for('entornos'))

    try:
        with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
            cursor.execute("UPDATE entorno SET entorno_name = %s WHERE identorno = %s", (nombre, identorno))
            conn.commit()
        flash(f'Entorno actualizado correctamente.', 'success')
    except Exception as e:
        flash(f'Error al actualizar entorno: {e}', 'danger')

    return redirect(url_for('entornos'))

# Eliminar entorno
@app.route('/entornos/eliminar/<int:identorno>', methods=['POST'])
def eliminar_entorno(identorno):
    try:
        with closing(get_db()) as conn, closing(conn.cursor()) as cursor:
            cursor.execute("DELETE FROM entorno WHERE identorno = %s", (identorno,))
            conn.commit()
        flash('Entorno eliminado correctamente.', 'success')
    except Exception as e:
        flash(f'Error al eliminar entorno: {e}', 'danger')

    return redirect(url_for('entornos'))


#####################################################################################################################################################################
## Control de Accesos
#####################################################################################################################################################################


@app.route('/accesos')
def accesos():
    if session.get('role') != 'admin':
        flash('No tienes permiso para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Obtener las selecciones
    cursor.execute("""
        SELECT s.idseleccion, s.seleccionado, s.webhook, s.notificaciones,
               r.remoto_name, p.proyecto_name, e.entorno_name, u.udp_name,
               s.seleccion_dato_remoto, s.seleccion_dato_proyecto, 
               s.seleccion_dato_entorno, s.seleccion_dato_udp
        FROM seleccion_check s
        JOIN remoto r ON s.seleccion_dato_remoto = r.remoto_code
        JOIN proyecto p ON s.seleccion_dato_proyecto = p.proyecto_code
        JOIN entorno e ON s.seleccion_dato_entorno = e.entorno_code
        JOIN udp u ON s.seleccion_dato_udp = u.udp_code
        ORDER BY s.idseleccion
    """)
    seleccionados = cursor.fetchall()

    # Traer datos para los selects del modal
    cursor.execute("SELECT remoto_code, remoto_name FROM remoto")
    remotos = cursor.fetchall()

    cursor.execute("SELECT proyecto_code, proyecto_name FROM proyecto")
    proyectos = cursor.fetchall()

    cursor.execute("SELECT entorno_code, entorno_name FROM entorno")
    entornos = cursor.fetchall()

    cursor.execute("SELECT udp_code, udp_name FROM udp")
    udps = cursor.fetchall()

    # Obtener el estado de apertura_libre
    cursor.execute("SELECT apertura_libre FROM configuracion LIMIT 1")
    config = cursor.fetchone()
    apertura_libre = config['apertura_libre'] if config else False

    cursor.close()
    conn.close()

    return render_template('accesos.html', 
                           user=session.get('username'), 
                           role=session.get('role'),
                           acceso_ftp=session.get('acceso_ftp'),
                           seleccionados=seleccionados,
                           remotos=remotos,
                           proyectos=proyectos,
                           entornos=entornos,
                           udps=udps,
                           apertura_libre=apertura_libre)


@app.route('/insert_seleccion', methods=['POST'])
def insert_seleccion():
    remoto = request.form.get('remoto')
    proyecto = request.form.get('proyecto')
    entorno = request.form.get('entorno')
    udp = request.form.get('udp')
    seleccionado = request.form.get('seleccionado')
    webhook = request.form.get('webhook', '')
    notificaciones = request.form.get('notificaciones', 0)

    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT IFNULL(MAX(seleccion_code), 5000) FROM seleccion_check")
        max_code = cursor.fetchone()[0]
        nuevo_code = max_code + 1

        cursor.execute("""
            INSERT INTO seleccion_check
            (seleccion_dato_remoto, seleccion_dato_proyecto, seleccion_dato_entorno, 
             seleccion_dato_udp, seleccion_code, seleccionado, webhook, notificaciones)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (remoto, proyecto, entorno, udp, nuevo_code, seleccionado, webhook, notificaciones))

        conn.commit()
        cursor.close()
        conn.close()

        flash(f"Acceso agregado correctamente", "success")

    except Exception as e:
        flash(f"Error al insertar el acceso: {str(e)}", "danger")

    return redirect(url_for('accesos'))

@app.route('/toggle_seleccion', methods=['POST'])
def toggle_seleccion():
    id_seleccion = request.form.get('id')
    seleccionado = request.form.get('seleccionado')

    if not id_seleccion or seleccionado is None:
        flash('Faltan datos para actualizar el acceso.', 'danger')
        return redirect(url_for('accesos'))

    try:
        seleccionado = int(seleccionado)

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Obtener is_admin y remoto_code del usuario actual
        cursor.execute("""
            SELECT is_admin, remoto_code 
            FROM users 
            WHERE username = %s
        """, (session.get('username'),))
        user_info = cursor.fetchone()

        if not user_info:
            flash("Usuario no encontrado.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('accesos'))

        # Obtener remoto del acceso que se intenta modificar
        cursor.execute("""
            SELECT seleccion_dato_remoto 
            FROM seleccion_check 
            WHERE idseleccion = %s
        """, (id_seleccion,))
        seleccion_info = cursor.fetchone()

        if not seleccion_info:
            flash("Acceso no encontrado.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('accesos'))

        # Validar si el usuario puede activar este acceso
        if seleccionado == 1:
            if not user_info['is_admin'] and user_info['remoto_code'] != seleccion_info['seleccion_dato_remoto']:
                flash("No puedes activar este acceso: el remoto asignado a tu usuario no coincide.", "danger")
                cursor.close()
                conn.close()
                return redirect(url_for('accesos'))

        # Si pasa la validación, actualizar
        cursor.execute("""
            UPDATE seleccion_check 
            SET seleccionado = %s 
            WHERE idseleccion = %s
        """, (seleccionado, id_seleccion))
        conn.commit()
        cursor.close()
        conn.close()

        mensaje = "Acceso activado correctamente." if seleccionado else "Acceso desactivado correctamente."
        flash(mensaje, 'success')

    except Exception as e:
        flash(f"Error al actualizar el acceso: {str(e)}", 'danger')

    return redirect(url_for('accesos'))

@app.route('/toggle_notificaciones', methods=['POST'])
def toggle_notificaciones():
    if 'username' not in session:
        flash('Debes iniciar sesión para realizar esta acción', 'danger')
        return redirect(url_for('login'))

    id_seleccion = request.form.get('id')
    notificaciones = request.form.get('notificaciones')

    if not id_seleccion or notificaciones is None:
        flash('Datos incompletos para la solicitud', 'danger')
        return redirect(url_for('accesos'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Verificar permisos del usuario
        cursor.execute("""
            SELECT u.is_admin, u.remoto_code, sc.seleccion_dato_remoto 
            FROM users u
            JOIN seleccion_check sc ON sc.idseleccion = %s
            WHERE u.username = %s
        """, (id_seleccion, session['username']))
        
        permiso = cursor.fetchone()
        
        if not permiso:
            flash('Acceso no encontrado o no tienes permisos', 'danger')
            return redirect(url_for('accesos'))

        if not permiso['is_admin'] and permiso['remoto_code'] != permiso['seleccion_dato_remoto']:
            flash('No tienes permisos para modificar estas notificaciones', 'warning')
            return redirect(url_for('accesos'))

        # Actualizar estado de notificaciones
        cursor.execute("""
            UPDATE seleccion_check 
            SET notificaciones = %s 
            WHERE idseleccion = %s
        """, (notificaciones, id_seleccion))
        
        conn.commit()
        flash('Estado de notificaciones actualizado correctamente', 'success')

    except Exception as e:
        conn.rollback()
        flash(f'Error al actualizar notificaciones: {str(e)}', 'danger')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('accesos'))

@app.route('/update_seleccion', methods=['POST'])
def update_seleccion():
    data = request.form
    id = data.get('id')
    remoto = data.get('remoto')
    proyecto = data.get('proyecto')
    entorno = data.get('entorno')
    udp = data.get('udp')
    seleccionado = data.get('seleccionado')
    webhook = data.get('webhook', '')
    notificaciones = data.get('notificaciones', 0)
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE seleccion_check 
            SET seleccion_dato_remoto = %s,
                seleccion_dato_proyecto = %s,
                seleccion_dato_entorno = %s,
                seleccion_dato_udp = %s,
                seleccionado = %s,
                webhook = %s,
                notificaciones = %s
            WHERE idseleccion = %s
        """, (remoto, proyecto, entorno, udp, seleccionado, webhook, notificaciones, id))
        conn.commit()
        
        flash("Selección actualizada correctamente", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error al actualizar selección: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('accesos'))

@app.route('/delete_seleccion', methods=['POST'])
def delete_seleccion():
    id = request.form.get('id')
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM seleccion_check WHERE idseleccion = %s", (id,))
        conn.commit()
        
        flash("Selección eliminada correctamente", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error al eliminar selección: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('accesos'))



############################################################################################################################################################
## Papelera 
############################################################################################################################################################


@app.route("/papelera")
def papelera():
    if session.get('role') != 'admin':
        flash('No tienes permiso para acceder a esta sección', 'danger')
        return redirect(url_for('home'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    try:
        # Consulta principal para obtener los elementos de la papelera
        cursor.execute("""
            SELECT 
                p.idpapelera,
                p.solicitud_usuario,
                p.tipo_opcion,
                p.folio,
                p.descripcion,
                p.fecha_creacion,
                p.fecha_eliminacion,
                p.acceso_bd,
                p.acceso_ftp,
                p.apertura_code,
                pr.proyecto_name,
                e.entorno_name,
                r.remoto_name,
                (SELECT COUNT(*) FROM papelera_imagenes WHERE idpapelera = p.idpapelera) AS total_imagenes
            FROM papelera p
            LEFT JOIN proyecto pr ON pr.proyecto_code = p.proyecto_code
            LEFT JOIN entorno e ON e.entorno_code = p.entorno_code
            LEFT JOIN remoto r ON r.remoto_code = p.solicitud_remoto
            ORDER BY p.fecha_eliminacion DESC
        """)
        papelera = cursor.fetchall()

        # Para cada elemento, obtener sus imágenes
        for item in papelera:
            cursor.execute("""
                SELECT imagen_path 
                FROM papelera_imagenes 
                WHERE idpapelera = %s
                ORDER BY idimagen_papelera ASC
            """, (item['idpapelera'],))
            item['imagenes'] = [img['imagen_path'] for img in cursor.fetchall()]

    except Exception as e:
        flash(f'Error al cargar la papelera: {str(e)}', 'danger')
        papelera = []
    finally:
        cursor.close()
        conn.close()

    return render_template("papelera.html", 
                         papelera=papelera, 
                         acceso_ftp=session.get('acceso_ftp'),
                         user=session.get('username'),
                         role=session.get('role'))

@app.route('/mover_a_papelera/<int:apertura_code>', methods=['POST'])
def mover_a_papelera(apertura_code):
    if session.get('role') != 'admin':
        flash('No tienes permisos para esta acción', 'danger')
        return redirect(url_for('login'))

    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # 1. Validación de existencia previa en papelera
        cursor.execute("SELECT 1 FROM papelera WHERE apertura_code = %s LIMIT 1", (apertura_code,))
        if cursor.fetchone():
            flash('Esta apertura ya está en la papelera.', 'info')
            return redirect(url_for('solicitudes', vista='finalizadas'))

        # 2. Obtener datos de la solicitud y apertura
        cursor.execute("""
            SELECT sa.*, af.idapertura, af.descripcion as descripcion_final
            FROM solicitud_apertura sa
            LEFT JOIN aperturas_finalizadas af ON sa.apertura_code = af.apertura_code
            WHERE sa.apertura_code = %s
        """, (apertura_code,))
        registro = cursor.fetchone()

        if not registro:
            flash('Registro no encontrado.', 'danger')
            return redirect(url_for('solicitudes', vista='finalizadas'))

        # 3. Insertar en papelera con transacción
        cursor.execute("""
            INSERT INTO papelera (
                solicitud_usuario, solicitud_remoto, tipo_opcion, folio,
                proyecto_code, entorno_code, acceso_bd, acceso_ftp,
                descripcion, apertura_code, fecha_creacion, fecha_eliminacion
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            registro['solicitud_usuario'],
            registro['solicitud_remoto'],
            registro['tipo_opcion'],
            registro['folio'],
            registro['proyecto_code'],
            registro['entorno_code'],
            registro['acceso_bd'],
            registro['acceso_ftp'],
            registro['descripcion_final'] or registro['descripcion'],
            registro['apertura_code'],
            registro['fecha_creacion']
        ))
        idpapelera = cursor.lastrowid

        # 4. Mover imágenes con información completa
        cursor.execute("""
            INSERT INTO papelera_imagenes (idpapelera, imagen_path, fecha_eliminacion)
            SELECT %s, imagen_path, NOW()
            FROM apertura_imagenes
            WHERE apertura_id = %s
        """, (idpapelera, registro['idapertura']))

        # 5. Eliminar registros originales con verificación
        if registro['idapertura']:
            cursor.execute("DELETE FROM apertura_imagenes WHERE apertura_id = %s", (registro['idapertura'],))
            cursor.execute("DELETE FROM aperturas_finalizadas WHERE idapertura = %s", (registro['idapertura'],))
        
        cursor.execute("DELETE FROM solicitud_apertura WHERE apertura_code = %s", (apertura_code,))

        conn.commit()
        
        # Registrar acción en log
        app.logger.info(f"Apertura {apertura_code} movida a papelera por {session.get('username')}")
        flash('Registro movido a la papelera correctamente.', 'success')

    except mysql.connector.Error as err:
        if conn:
            conn.rollback()
        app.logger.error(f"Error al mover a papelera: {err}")
        flash('Ocurrió un error al mover el registro a la papelera.', 'danger')
    except Exception as e:
        if conn:
            conn.rollback()
        app.logger.error(f"Error inesperado: {e}")
        flash('Error inesperado al procesar la solicitud.', 'danger')
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

    return redirect(url_for('solicitudes', vista='finalizadas'))

@app.route('/eliminar_seleccionados', methods=['POST'])
def eliminar_seleccionados():
    if session.get('role') != 'admin':
        flash('No tienes permiso para realizar esta acción', 'danger')
        return redirect(url_for('papelera'))

    data = request.get_json()
    if not data or 'items' not in data:
        flash('Datos inválidos para la eliminación', 'danger')
        return redirect(url_for('papelera'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    success_count = 0
    error_count = 0

    try:
        for item in data['items']:
            apertura_code = item.get('apertura_code')
            folio = item.get('folio')

            try:
                # 1. Eliminar imágenes asociadas de papelera_imagenes
                cursor.execute("""
                    DELETE FROM papelera_imagenes 
                    WHERE idpapelera IN (
                        SELECT idpapelera FROM papelera WHERE apertura_code = %s
                    )
                """, (apertura_code,))

                # 2. Eliminar registro de la papelera
                cursor.execute("DELETE FROM papelera WHERE apertura_code = %s", (apertura_code,))

                # 3. Eliminar registro de solicitud_apertura si existe
                cursor.execute("DELETE FROM solicitud_apertura WHERE apertura_code = %s", (apertura_code,))

                success_count += 1
            except Exception as e:
                error_count += 1
                print(f"Error al eliminar elemento {apertura_code}: {str(e)}")

        conn.commit()

        if success_count > 0:
            flash(f'Se eliminaron correctamente {success_count} elementos', 'success')
        if error_count > 0:
            flash(f'Hubo problemas al eliminar {error_count} elementos', 'warning')

    except Exception as e:
        conn.rollback()
        flash(f'Error grave al eliminar elementos: {str(e)}', 'danger')
    finally:
        cursor.close()
        conn.close()

    return jsonify({'redirect': url_for('papelera')})


#####################################################################################################################################################################
## Sistema de Logs
#####################################################################################################################################################################


@app.route('/logs')
def logs():
    if session.get('role') != 'admin':
        flash('No tienes permiso para realizar esta acción', 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # Logs del sistema
    cursor.execute("""
        SELECT * FROM logs_sistema
        ORDER BY fecha_evento DESC
        LIMIT 100
    """)
    registros = cursor.fetchall()

    # Configuración del webhook
    cursor.execute("SELECT * FROM webhook_logs LIMIT 1")
    webhook = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template(
        "logs.html",
        registros=registros,
        webhook=webhook, 
        acceso_ftp=session.get('acceso_ftp'),
        user=session.get('username'),
        role=session.get('role')
    )



def registrar_log(tipo_evento, descripcion, usuario):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO logs_sistema (tipo_evento, descripcion, usuario)
            VALUES (%s, %s, %s)
        """, (tipo_evento, descripcion, usuario))
        conn.commit()
    except Exception as e:
        print(f"[ERROR] No se pudo registrar el log: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()


@app.route('/config_webhook', methods=['POST'])
def config_webhook():
    webhook_url = request.form.get('webhook_url')
    notificaciones = 1 if request.form.get('notificaciones') == '1' else 0

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM webhook_logs LIMIT 1")
    existe = cursor.fetchone()

    if existe:
        cursor.execute("""
            UPDATE webhook_logs
            SET webhook_url = %s, notificaciones = %s
            WHERE id = %s
        """, (webhook_url, notificaciones, existe[0]))
    else:
        cursor.execute("""
            INSERT INTO webhook_logs (webhook_url, notificaciones)
            VALUES (%s, %s)
        """, (webhook_url, notificaciones))

    conn.commit()
    flash('Configuración de webhook actualizada correctamente.', 'success')
    return redirect(url_for('logs'))


#####################################################################################################################################################################
## Sistema de FTP
#####################################################################################################################################################################

# FTP
FTP_HOST = 'land1.qatesting.app'
FTP_PORT = 21
FTP_USER = 'temporal10@land1.qatesting.app'
FTP_PASS = '0pS3i6mnH0yj7aS'
REMOTE_DIR = '/'

@app.route('/descargaFTP', methods=['GET', 'POST'])
def descargaFTP():
    archivos = []
    usuario = session.get('username')

    if not usuario:
        flash("Debes iniciar sesión para usar esta función.", "danger")
        return redirect(url_for('login'))

    def obtener_nombre_remoto():
        try:
            conn = get_db()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT r.remoto_name
                FROM users u
                JOIN remoto r ON u.remoto_code = r.remoto_code
                WHERE u.username = %s
            """, (usuario,))
            resultado = cursor.fetchone()
            cursor.close()
            conn.close()
            return resultado['remoto_name'] if resultado else "Servidor desconocido"
        except Exception as e:
            print(f"[X] Error obteniendo nombre del servidor remoto: {e}")
            return "Servidor desconocido"

    remoto_nombre = obtener_nombre_remoto()  # <-- ¡Ahora disponible desde el inicio!

    def registrar_log(tipo_evento, descripcion, remoto=None, total_archivos=None, peso_mb=None):
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO logs_sistema (fecha_evento, tipo_evento, descripcion, usuario)
                VALUES (%s, %s, %s, %s)
            """, (datetime.now(), tipo_evento, descripcion, usuario))
            conn.commit()

            cursor.execute("SELECT webhook_url FROM webhook_logs WHERE notificaciones = 1 LIMIT 1")
            resultado = cursor.fetchone()

            if resultado and ("Transferencia completa" in tipo_evento or "Error general" in tipo_evento):
                webhook_url = resultado[0]
                embed = {
                    "title": tipo_evento,
                    "color": 0x2ecc71 if "completa" in tipo_evento else 0xe74c3c,
                    "fields": [
                        {"name": "Fecha y Hora", "value": datetime.now().strftime("%d/%m/%Y %H:%M:%S")},
                        {"name": "Usuario", "value": usuario},
                        {"name": "Servidor Remoto", "value": remoto or "Desconocido"}
                    ],
                    "timestamp": datetime.now().isoformat()
                }
                if total_archivos is not None and peso_mb is not None:
                    embed["fields"].append({"name": "Cantidad de Archivos", "value": str(total_archivos)})
                    embed["fields"].append({"name": "Tamaño Total (MB)", "value": f"{peso_mb:.2f}"})

                requests.post(webhook_url, json={"embeds": [embed]})

            cursor.close()
            conn.close()

        except Exception as e:
            print(f"[X] Error registrando log o enviando a Discord: {e}")

    def descargar_y_eliminar_todo(ftp, remote_path, local_path, remoto):
        os.makedirs(local_path, exist_ok=True)
        total_archivos = 0
        total_peso_bytes = 0

        try:
            entries = list(ftp.mlsd(remote_path))
        except Exception:
            try:
                entries = [(name, {}) for name in ftp.nlst(remote_path)]
            except Exception as e:
                registrar_log("Descarga FTP - Error", f"No se pudo listar {remote_path}: {e}", remoto=remoto)
                return 0, 0

        for name, facts in entries:
            if name in ['.', '..']:
                continue

            ruta_remota = f"{remote_path}/{name}".replace('//', '/')
            ruta_local = os.path.join(local_path, name)

            es_dir = facts.get('type') == 'dir' if facts else False

            if not facts:
                try:
                    ftp.cwd(ruta_remota)
                    es_dir = True
                    ftp.cwd(remote_path)
                except:
                    es_dir = False

            if es_dir:
                sub_archivos, sub_peso = descargar_y_eliminar_todo(ftp, ruta_remota, ruta_local, remoto)
                total_archivos += sub_archivos
                total_peso_bytes += sub_peso
                try:
                    ftp.rmd(ruta_remota)
                    registrar_log("Descarga FTP - Carpeta eliminada", f"Directorio eliminado: {ruta_remota}", remoto=remoto)
                except Exception as e:
                    registrar_log("Descarga FTP - Error", f"No se pudo eliminar directorio {ruta_remota}: {e}", remoto=remoto)
            else:
                try:
                    with open(ruta_local, 'wb') as f:
                        ftp.retrbinary(f"RETR {ruta_remota}", f.write)
                    peso = os.path.getsize(ruta_local)
                    total_archivos += 1
                    total_peso_bytes += peso
                    registrar_log("Descarga FTP - Archivo descargado", f"{name} guardado en {ruta_local}", remoto=remoto)
                except Exception as e:
                    registrar_log("Descarga FTP - Error", f"Error descargando {ruta_remota}: {e}", remoto=remoto)
                    continue

                try:
                    ftp.delete(ruta_remota)
                    registrar_log("Descarga FTP - Archivo eliminado", f"{name} eliminado del FTP", remoto=remoto)
                except Exception as e:
                    registrar_log("Descarga FTP - Error", f"No se pudo eliminar archivo {ruta_remota}: {e}", remoto=remoto)

        return total_archivos, total_peso_bytes

    if request.method == 'POST':
        accion = request.form.get('accion')

        try:
            with FTP() as ftp:
                ftp.connect(FTP_HOST, FTP_PORT)
                ftp.login(FTP_USER, FTP_PASS)
                ftp.cwd(REMOTE_DIR)
                archivos = ftp.nlst()

                if not archivos:
                    flash("El servidor FTP está vacío.", 'warning')
                    registrar_log("Descarga FTP - Vacío", "Servidor FTP vacío.", remoto=remoto_nombre)
                else:
                    if accion == 'buscar':
                        flash(f"Se encontraron {len(archivos)} archivos/directorios en el FTP.", 'success')
                        registrar_log("Descarga FTP - Búsqueda", f"{len(archivos)} elementos encontrados por {usuario}.", remoto=remoto_nombre)
                    elif accion == 'transferir':
                        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                        destino = os.path.join('C:\\Compartidos\\Descargas', timestamp)
                        os.makedirs(destino, exist_ok=True)

                        total_archivos, peso_bytes = descargar_y_eliminar_todo(ftp, '.', destino, remoto_nombre)
                        peso_mb = peso_bytes / (1024 * 1024)

                        flash(f'Archivos descargados del FTP exitosamente en: {destino}', 'success')
                        registrar_log(
                            "Descarga FTP - Transferencia completa",
                            f"{usuario} transfirió archivos al directorio {destino}.",
                            remoto=remoto_nombre,
                            total_archivos=total_archivos,
                            peso_mb=peso_mb
                        )

        except Exception as e:
            registrar_log("Descarga FTP - Error general", f"{usuario} tuvo error: {e}", remoto=remoto_nombre)
            flash(f'Error en la conexión FTP: {e}', 'danger')

    return render_template(
        "descargaFTP.html",
        acceso_ftp=session.get('acceso_ftp'),
        user=usuario,
        role=session.get('role'),
        archivos=archivos
    )



# #####################################################################################################################################################################
# Sistema de notificacion Discord
# #####################################################################################################################################################################

# Al crear la apertura, insertar webhook en la tabla nueva
def guardar_webhook_apertura(apertura_code, webhook_url, notificaciones=1):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO webhook_seleccion (apertura_code, webhook, notificaciones)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE webhook = VALUES(webhook), notificaciones = VALUES(notificaciones)
    """, (apertura_code, webhook_url, notificaciones))
    conn.commit()
    cursor.close()
    conn.close()

def obtener_webhook_por_apertura(apertura_code):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT webhook FROM webhook_seleccion 
        WHERE apertura_code = %s AND notificaciones = 1
        LIMIT 1
    """, (apertura_code,))
    resultado = cursor.fetchone()
    cursor.close()
    conn.close()
    return resultado['webhook'] if resultado else None

def eliminar_webhook_por_apertura(apertura_code):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM webhook_seleccion WHERE apertura_code = %s", (apertura_code,))
    conn.commit()
    cursor.close()
    conn.close()


def enviar_notificacion_discord(usuario, proyecto, entorno, tiempo_restante, acceso_bd=False, acceso_ftp=False, folio=None, apertura_code=None, tipo_opcion=None):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Obtener los webhooks configurados
        cursor.execute("""
            SELECT webhook 
            FROM seleccion_check 
            WHERE seleccion_dato_proyecto = (
                SELECT proyecto_code FROM proyecto WHERE proyecto_name = %s
            )
            AND seleccion_dato_entorno = (
                SELECT entorno_code FROM entorno WHERE entorno_name = %s
            )
            AND notificaciones = 1
            AND webhook IS NOT NULL
            AND webhook != ''
        """, (proyecto, entorno))
        
        webhooks = cursor.fetchall()

        # ⚠️ Si no hay webhooks, retorna lista vacía
        if not webhooks:
            print("No hay webhooks configurados o notificaciones desactivadas para esta combinación proyecto-entorno")
            return []

        # Armar mensaje Discord (esto ya lo tienes bien)
        fields = [
            {"name": "👤 Usuario", "value": usuario, "inline": False},
            {"name": "📁 Proyecto", "value": proyecto, "inline": False},
            {"name": "🏗️ Entorno", "value": entorno, "inline": False},
            {"name": "🕒 Fecha y hora de solicitud", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": False},
            {"name": "⏳ Tiempo de apertura", "value": f"{tiempo_restante} minutos", "inline": False}
        ]

        if folio and tipo_opcion:
            fields.append({
                "name": "🧾 Folio / Tarea",
                "value": f"{tipo_opcion}: #{folio}",
                "inline": False
            })

        if apertura_code:
            fields.insert(0, {
                "name": "🔢 Código de apertura",
                "value": f"#{apertura_code}",
                "inline": False
            })

        accesos_seleccionados = []
        if acceso_bd:
            accesos_seleccionados.append("Base de datos")
        if acceso_ftp:
            accesos_seleccionados.append("FTP")

        if accesos_seleccionados:
            fields.append({
                "name": "🔑 Accesos otorgados",
                "value": ", ".join(accesos_seleccionados),
                "inline": False
            })

        embed = {
            "title": "🔐 Solicitud de apertura de puertos",
            "color": 0x2ECC71,
            "fields": fields,
            "footer": {"text": "Sistema Apleeks · Seguridad de red"}
        }

        data = {"username": "Apleeks Bot", "embeds": [embed]}

        # Enviar a cada webhook
        utilizados = []
        for webhook in webhooks:
            try:
                response = requests.post(webhook['webhook'], json=data)
                if response.status_code == 204:
                    utilizados.append(webhook['webhook'])
                else:
                    print(f"❌ Falló el envío a Discord: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"❌ Error al enviar notificación a Discord: {e}")

        return utilizados

    finally:
        cursor.close()
        conn.close()




def notificar_expiracion(apertura_code, usuario, proyecto, entorno, folio, tipo_opcion, acceso_bd, acceso_ftp, tiempo_asignado):
    webhook_url = obtener_webhook_por_apertura(apertura_code)
    if not webhook_url:
        print("No hay webhook para esta apertura")
        return False

    # Construir payload para expiración (puedes usar tu función ya creada)
    payload = {
        "username": "Apleeks Bot",
        "embeds": [
            {
                "title": "⛔ Conexión expirada automáticamente",
                "color": 0xF39C12,
                "fields": [
                    {"name": "🔢 Código de apertura", "value": f"#{apertura_code}", "inline": False},
                    {"name": "👤 Usuario", "value": usuario, "inline": False},
                    {"name": "📁 Proyecto", "value": proyecto, "inline": False},
                    {"name": "🏗️ Entorno", "value": entorno, "inline": False},
                    {"name": "🧾 Folio", "value": f"#{folio}" if folio else "N/A", "inline": False},
                    {"name": "⏳ Tiempo asignado", "value": f"{tiempo_asignado} minutos", "inline": False},
                    {"name": "🔑 Accesos usados", "value": ", ".join(filter(None, ["Base de datos" if acceso_bd else None, "FTP" if acceso_ftp else None])), "inline": False},
                    {"name": "🕒 Fecha y hora de expiración", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": False}
                ],
                "footer": {"text": "Sistema Apleeks · Seguridad de red"}
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 204:
            print("Notificación de expiración enviada")
        else:
            print(f"Error al enviar notificación de expiración: {response.status_code} {response.text}")
    except Exception as e:
        print(f"Excepción al enviar notificación: {e}")
    return True




def notificar_finalizacion(apertura_code, usuario, proyecto, entorno, acceso_bd, acceso_ftp, folio, tipo_opcion, tiempo_resolucion):
    webhook_url = obtener_webhook_por_apertura(apertura_code)
    if not webhook_url:
        print("No hay webhook para esta apertura")
        return False

    payload = {
        "username": "Apleeks Bot",
        "embeds": [
            {
                "title": "✅ Solicitud de apertura finalizada",
                "color": 0xE74C3C,
                "fields": [
                    {"name": "🔢 Código de apertura", "value": f"#{apertura_code}", "inline": False},
                    {"name": "👤 Usuario", "value": usuario, "inline": False},
                    {"name": "📁 Proyecto", "value": proyecto, "inline": False},
                    {"name": "🏗️ Entorno", "value": entorno, "inline": False},
                    {"name": "🕒 Fecha y hora de cierre", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": False},
                    {"name": "⏱️ Duración total", "value": tiempo_resolucion, "inline": False},
                    {"name": "🧾 Folio", "value": f"#{folio}" if folio else "N/A", "inline": False},
                    {"name": "🔑 Accesos usados", "value": ", ".join(filter(None, ["Base de datos" if acceso_bd else None, "FTP" if acceso_ftp else None])), "inline": False}
                ],
                "footer": {"text": "Sistema Apleeks · Seguridad de red"}
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 204:
            print("Notificación de finalización enviada")
        else:
            print(f"Error al enviar notificación de finalización: {response.status_code} {response.text}")
    except Exception as e:
        print(f"Excepción al enviar notificación: {e}")

    eliminar_webhook_por_apertura(apertura_code)
    return True





# ============================
#     EJECUCIÓN FLASK
# ============================

if __name__ == '__main__':
    app.run(debug=True, port=8082)

