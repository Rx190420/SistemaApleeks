from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask import send_from_directory
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from contextlib import closing
from datetime import time
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import requests
import mysql.connector
import socket
import threading
import time
import os
import re
import os

app = Flask(__name__)

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
    'user': 'root',
    'password': '12345678',
    'database': 'utpDB'
}

@app.route('/uploads/<path:filename>')
def uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.context_processor
def inject_now():
    return {'now': datetime.now}

from flask import jsonify, request, session, flash
from datetime import datetime
import re

@app.route('/actualizar_tiempo_apertura', methods=['POST'])
def actualizar_tiempo_apertura():
    if 'username' not in session:
        return jsonify({"error": "No autenticado"}), 401

    data = request.get_json()
    apertura_code = data.get('apertura_code')
    tiempo_restante = data.get('tiempo_restante', '')  # Formato HH:MM:SS

    # Validación básica del formato
    if not re.match(r'^\d{2}:\d{2}:\d{2}$', tiempo_restante):
        return jsonify({"error": "Formato de tiempo no válido"}), 400

    # Verificar si el tiempo ha expirado (00:00:00)
    if tiempo_restante == "00:00:00":
        return jsonify({"expired": True, "message": "El tiempo de apertura ha expirado"}), 200

    # En esta versión simplificada, no actualizamos nada en la base de datos
    # Solo respondemos que el tiempo aún no ha expirado
    return jsonify({"success": True, "message": "Tiempo actualizado"})



def get_db():
    return mysql.connector.connect(**db_config)

# ========== FUNCIONALIDAD: PORT KNOCKING ==========
def hacer_port_knocking(ip, puertos):
    for puerto in puertos:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b'knock', (ip, int(puerto)))
            sock.close()
        except Exception as e:
            print(f"Error al hacer knock en puerto {puerto}: {e}")
# ========== PROCESAR APERTURAS ==========
from datetime import datetime, time

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


# ============================
#     RUTAS DE NAVEGACIÓN
# ============================

@app.route('/')
def index():
    return redirect(url_for('login'))

# ============================
#          LOGIN
# ============================

@app.route('/login', methods=['GET', 'POST'])
def login():
    mensaje = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)

            cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
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
        return 1  # Empieza en 0001
    else:
        return resultado[0] + 1
    
@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = session['username']
    role = session.get('role')
    remoto_nombre = None

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # Validar si ya tiene una apertura activa
    cursor.execute("""
        SELECT sa.*, ai.apertura_tiempo, ai.fecha_apertura
        FROM solicitud_apertura sa
        JOIN aperturas_iniciadas ai ON sa.apertura_code = ai.apertura_code
        WHERE sa.solicitud_usuario = %s
          AND EXISTS (
              SELECT 1 FROM aperturas_iniciadas ai
              WHERE ai.apertura_code = sa.apertura_code
          )
        LIMIT 1
    """, (user,))
    ya_tiene_apertura = cursor.fetchone()

    if request.method == 'POST':
        if ya_tiene_apertura:
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
        cursor.execute("""
            SELECT remoto_code 
            FROM users 
            WHERE username = %s
        """, (user,))
        user_remoto_info = cursor.fetchone()

        if not user_remoto_info or user_remoto_info['remoto_code'] is None:
            flash("Tu usuario no tiene un servidor remoto asignado. Contacta al administrador.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for('home'))

        usuario_remoto_code = user_remoto_info['remoto_code']

        # Verificar si existe un acceso activo
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
            flash("No tienes permiso para esta apertura: el acceso activo no corresponde con tu servidor remoto, proyecto y entorno.", "danger")
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

        # Insertar solicitud de apertura
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
        duracion_minutos = 1  # Duración en minutos (puedes cambiarlo según necesites)
        tiempo_limite_str = f"00:{duracion_minutos:02d}:00"  # Formato HH:MM:SS

        # Ejecutar port knocking
        hacer_port_knocking(ip, puertos)

        # Obtener nombres para notificación
        cursor.execute("SELECT proyecto_name FROM proyecto WHERE proyecto_code = %s", (proyecto,))
        proyecto_nombre = cursor.fetchone()['proyecto_name']

        cursor.execute("SELECT entorno_name FROM entorno WHERE entorno_code = %s", (entorno,))
        entorno_nombre = cursor.fetchone()['entorno_name']

        # Cuando se crea la apertura:
        webhooks_utilizados = enviar_notificacion_discord(user, proyecto_nombre, entorno_nombre, duracion_minutos,
                                acceso_bd=acceso_bd, acceso_ftp=acceso_ftp,
                                folio=folio, apertura_code=apertura_code,
                                tipo_opcion=opcion)

        # Guardar los webhooks en la sesión
        session['webhooks_notificacion'] = webhooks_utilizados
        session.modified = True  # Asegurar que la sesión se guarde

        cursor.execute("""
            INSERT INTO aperturas_iniciadas (apertura_code, apertura_tiempo, fecha_apertura)
            VALUES (%s, %s, %s)
        """, (apertura_code, tiempo_limite_str, now))

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

    threading.Thread(target=mover_a_finalizadas).start()

    return render_template("home.html", 
                         proyectos=proyectos, 
                         entornos=entornos,
                         remoto_nombre=remoto_nombre, 
                         user=user, 
                         role=role,
                         solicitud=ya_tiene_apertura)  # Pasar la solicitud activa si existe




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
        LIMIT 1
    """, (usuario,))
    solicitud = cursor.fetchone()

    cursor.close()
    conn.close()

    if not solicitud:
        flash("No tienes una apertura activa actualmente.", "warning")
        return redirect(url_for('home'))

    return render_template('solicitud_en_curso.html',
                           user=usuario,
                           role=session.get('role'),
                           solicitud=solicitud,
                           remoto_nombre=solicitud['remoto_nombre'])

@app.route('/iniciar_apertura', methods=['POST'])
def iniciar_apertura():
    if 'username' not in session:
        return jsonify({"error": "No autenticado"}), 401

    apertura_code = request.form.get('apertura_code')
    tiempo_inicial = request.form.get('tiempo_inicial')  # Ej: "01:00:00"

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
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()

    return jsonify({"success": True})




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
    tiempo_resolucion = str(fecha_final - fecha_inicio).split('.')[0]  # Formato HH:MM:SS

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

    # Obtener nombres de proyecto y entorno para la notificación
    cursor.execute("SELECT proyecto_name FROM proyecto WHERE proyecto_code = %s", (apertura['proyecto_code'],))
    proyecto_nombre = cursor.fetchone()['proyecto_name']

    cursor.execute("SELECT entorno_name FROM entorno WHERE entorno_code = %s", (apertura['entorno_code'],))
    entorno_nombre = cursor.fetchone()['entorno_name']

    # En la ruta /finalizar_apertura:
    webhooks = session.get('webhooks_notificacion', [])

    enviar_notificacion_finalizacion_discord(
        usuario,
        proyecto_nombre,
        entorno_nombre,
        acceso_bd=apertura.get('acceso_bd', False),
        acceso_ftp=apertura.get('acceso_ftp', False),
        folio=apertura.get('folio'),
        tipo_opcion=apertura.get('tipo_opcion'),
        apertura_code=apertura.get('apertura_code'),
        tiempo_resolucion=tiempo_resolucion,
        webhooks=webhooks
    )


    conexion.commit()
    cursor.close()
    conexion.close()

    flash("Acceso finalizado. Conexión cerrada y datos guardados correctamente.", "success")
    return redirect(url_for('apertura'))


def parse_fecha(fecha_str):
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(fecha_str, fmt)
        except ValueError:
            continue
    return None



@app.route('/actividades')
def actividades():
    if 'username' not in session:
        return redirect(url_for('login'))

    def parse_fecha_apertura(fecha_str):
        try:
            return datetime.strptime(fecha_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            return datetime.strptime(fecha_str, "%Y-%m-%d %H:%M:%S")

    def parse_hora(hora_str):
        try:
            return datetime.strptime(hora_str, "%H:%M:%S.%f").time()
        except ValueError:
            return datetime.strptime(hora_str, "%H:%M:%S").time()

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT ai.*, 
               sa.solicitud_usuario, sa.folio, sa.tipo_opcion,
               sa.acceso_bd, sa.acceso_ftp, sa.descripcion,
               sa.proyecto_code, sa.entorno_code,
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
        apertura_tiempo = act['apertura_tiempo']
        if isinstance(apertura_tiempo, str):
            apertura_tiempo = parse_hora(apertura_tiempo)

        # Verifica si el tiempo está en cero
        if apertura_tiempo == time(0, 0, 0):
            act['estado'] = 'expirada'
        else:
            act['estado'] = 'activa'

        # Convertir tiempo para mostrarlo en la plantilla
        act['apertura_tiempo_str'] = apertura_tiempo.strftime("%H:%M:%S")

        fecha_apertura = act['fecha_apertura']
        if isinstance(fecha_apertura, str):
            fecha_apertura = parse_fecha_apertura(fecha_apertura)
        act['fecha_apertura_str'] = fecha_apertura.strftime("%d/%m/%Y %H:%M:%S")

    cursor.close()
    conn.close()

    return render_template(
        "actividades.html",
        user=session['username'],
        role=session.get('role'),
        actividades=actividades
    )


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
        user=user,
        role=role,
        aperturas=aperturas,
        vista='finalizadas',
        total_pendientes=0
    )



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
                r.remoto_name
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
        usuarios=usuarios,
        remotos=remotos,
        active_tab='usuarios'
    )


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



@app.route('/puertosUDP')
def puertosUDP():
    if session.get('role') != 'admin':
        flash('No tienes permiso para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))
    with closing(get_db()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM udp ORDER BY idudp")
        udps = cursor.fetchall()
    return render_template('puertosUDP.html', udps=udps, user=session.get('username'), role=session.get('role'))

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



@app.route('/remotos')
def remotos():
    if session.get('role') != 'admin':
        flash('No autorizado', 'danger')
        return redirect(url_for('home'))
    with closing(get_db()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM remoto ORDER BY idremoto")
        remotos = cursor.fetchall()
    return render_template('remotos.html', remotos=remotos, user=session.get('username'), role=session.get('role'))

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


@app.route('/proyectos')
def proyectos():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('login'))

    with closing(get_db()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM proyecto ORDER BY idproyecto ASC")
        proyectos = cursor.fetchall()

    return render_template('proyectos.html', proyectos=proyectos, user=session['username'], role=session['role'])


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



@app.route('/entornos')
def entornos():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Acceso no autorizado', 'danger')
        return redirect(url_for('login'))

    with closing(get_db()) as conn, closing(conn.cursor(dictionary=True)) as cursor:
        cursor.execute("SELECT * FROM entorno ORDER BY identorno ASC")
        entornos = cursor.fetchall()

    return render_template('entornos.html', entornos=entornos, user=session['username'], role=session['role'])

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


@app.route('/accesos')
def accesos():
    if session.get('role') != 'admin':
        flash('No tienes permiso para acceder a esta sección.', 'danger')
        return redirect(url_for('home'))

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Traer datos de seleccion_check con joins (incluyendo nuevos campos)
    cursor.execute("""
        SELECT s.idseleccion, s.seleccionado, s.webhook, s.notificaciones,
               r.remoto_name, p.proyecto_name, e.entorno_name, u.udp_name
        FROM seleccion_check s
        JOIN remoto r ON s.seleccion_dato_remoto = r.remoto_code
        JOIN proyecto p ON s.seleccion_dato_proyecto = p.proyecto_code
        JOIN entorno e ON s.seleccion_dato_entorno = e.entorno_code
        JOIN udp u ON s.seleccion_dato_udp = u.udp_code
        ORDER BY s.idseleccion
    """)
    seleccionados = cursor.fetchall()

    # Datos para selects del modal
    cursor.execute("SELECT remoto_code, remoto_name FROM remoto")
    remotos = cursor.fetchall()

    cursor.execute("SELECT proyecto_code, proyecto_name FROM proyecto")
    proyectos = cursor.fetchall()

    cursor.execute("SELECT entorno_code, entorno_name FROM entorno")
    entornos = cursor.fetchall()

    cursor.execute("SELECT udp_code, udp_name FROM udp")
    udps = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('accesos.html', 
                           user=session.get('username'), 
                           role=session.get('role'),
                           seleccionados=seleccionados,
                           remotos=remotos,
                           proyectos=proyectos,
                           entornos=entornos,
                           udps=udps)

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




# ==========================
# API INSERT SELECCION
# ==========================

def enviar_notificacion_discord(usuario, proyecto, entorno, tiempo_restante, acceso_bd=False, acceso_ftp=False, folio=None, apertura_code=None, tipo_opcion=None):
    # Get database connection
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get all active webhooks with notifications enabled for this project and environment
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
        
        if not webhooks:
            print("No hay webhooks configurados o notificaciones desactivadas para esta combinación proyecto-entorno")
            return

        fields = [
            {"name": "👤 Usuario", "value": usuario, "inline": False},
            {"name": "📁 Proyecto", "value": proyecto, "inline": False},
            {"name": "🏗️ Entorno", "value": entorno, "inline": False},
            {"name": "🕒 Fecha y hora de solicitud", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": False},
            {"name": "⏳ Tiempo de apertura", "value": f"{tiempo_restante} minutos", "inline": False}
        ]

        if folio and tipo_opcion:
            tipo_label = "Ticket" if tipo_opcion.lower() == "Ticket" else "Tarea"
            fields.append({
                "name": f"🧾 {tipo_label}",
                "value": f"#{folio}",
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
            "footer": {
                "text": "Sistema Apleeks · Seguridad de red"
            }
        }

        data = {
            "username": "Apleeks Bot",
            "embeds": [embed]
        }

        # Send to all matching webhooks
        for webhook in webhooks:
            try:
                response = requests.post(webhook['webhook'], json=data)
                if response.status_code != 204:
                    print(f"❌ Falló el envío a Discord (webhook: {webhook['webhook']}): {response.status_code} - {response.text}")
            except Exception as e:
                print(f"❌ Error al enviar notificación a Discord (webhook: {webhook['webhook']}): {e}")
                
    finally:
        cursor.close()
        conn.close()



@app.route('/enviar_notificacion_expiracion', methods=['POST'])
def enviar_notificacion_expiracion():
    if 'username' not in session:
        return jsonify({"success": False, "error": "No autenticado"}), 401

    data = request.get_json()
    
    usuario = data.get('usuario', session.get('username', 'Desconocido'))
    proyecto = data.get('proyecto', 'Desconocido')
    entorno = data.get('entorno', 'Desconocido')
    folio = data.get('folio')
    tipo_opcion = data.get('tipo_opcion')
    acceso_bd = data.get('acceso_bd', False)
    acceso_ftp = data.get('acceso_ftp', False)
    apertura_code = data.get('apertura_code')
    tiempo_asignado = data.get('tiempo_asignado', 'Desconocido')

    # Obtener webhooks de la sesión
    webhooks = session.get('webhooks_notificacion', [])
    
    if not webhooks:
        print("⚠️ No se encontraron webhooks en la sesión para notificación de expiración")
        return jsonify({"success": False, "error": "No hay webhooks configurados"})

    # Construir el embed
    fields = []

    if apertura_code:
        fields.append({
            "name": "🔢 Código de apertura",
            "value": f"#{apertura_code}",
            "inline": False
        })

    fields.extend([
        {"name": "👤 Usuario", "value": usuario, "inline": False},
        {"name": "📁 Proyecto", "value": proyecto, "inline": False},
        {"name": "🏗️ Entorno", "value": entorno, "inline": False},
        {"name": "⏳ Tiempo asignado", "value": f"{tiempo_asignado} minutos", "inline": False},
        {"name": "🕒 Fecha y hora de expiración", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": False}
    ])

    if folio and tipo_opcion:
        tipo_label = "Ticket" if tipo_opcion.lower() == "ticket" else "Tarea"
        fields.append({
            "name": f"🧾 {tipo_label}",
            "value": f"#{folio}",
            "inline": False
        })

    accesos_usados = []
    if acceso_bd:
        accesos_usados.append("Base de datos")
    if acceso_ftp:
        accesos_usados.append("FTP")

    if accesos_usados:
        fields.append({
            "name": "🔑 Accesos usados",
            "value": ", ".join(accesos_usados),
            "inline": False
        })

    embed = {
        "title": "⛔ Conexión expirada automáticamente",
        "color": 0xE74C3C,  # Rojo
        "fields": fields,
        "footer": {
            "text": "Sistema Apleeks · Seguridad de red"
        }
    }

    payload = {
        "username": "Apleeks Bot",
        "embeds": [embed]
    }

    # Enviar a todos los webhooks guardados
    resultados = []
    for webhook_url in webhooks:
        try:
            response = requests.post(webhook_url, json=payload, timeout=5)
            if response.status_code == 204:
                resultados.append({"webhook": webhook_url, "status": "success"})
            else:
                resultados.append({
                    "webhook": webhook_url,
                    "status": "error",
                    "message": f"{response.status_code} - {response.text}"
                })
                print(f"❌ Falló el envío a Discord (webhook: {webhook_url}): {response.status_code} - {response.text}")
        except Exception as e:
            resultados.append({
                "webhook": webhook_url,
                "status": "exception",
                "message": str(e)
            })
            print(f"❌ Error al enviar notificación a Discord (webhook: {webhook_url}): {e}")

    # Verificar si al menos un webhook tuvo éxito
    success = any(r['status'] == 'success' for r in resultados)

    return jsonify({
        "success": success,
        "results": resultados
    })



def enviar_notificacion_finalizacion_discord(usuario, proyecto, entorno, acceso_bd=False, acceso_ftp=False, 
                                           folio=None, tipo_opcion=None, apertura_code=None, 
                                           tiempo_resolucion=None, webhooks=None):
    """
    Envía notificación de finalización a Discord usando los mismos webhooks que la notificación inicial.
    
    Args:
        usuario (str): Nombre del usuario que realizó la apertura
        proyecto (str): Nombre del proyecto
        entorno (str): Nombre del entorno
        acceso_bd (bool): Indica si se dio acceso a base de datos
        acceso_ftp (bool): Indica si se dio acceso FTP
        folio (str): Número de ticket/tarea asociado
        tipo_opcion (str): Tipo de opción (Ticket/Tarea)
        apertura_code (int): Código único de la apertura
        tiempo_resolucion (str): Duración total de la sesión
        webhooks (list): Lista de URLs de webhooks de Discord guardados en sesión
    
    Returns:
        bool: True si al menos un webhook recibió la notificación correctamente
    """
    
    # Si no se proporcionan webhooks, intentar obtenerlos de la sesión
    if webhooks is None:
        webhooks = session.get('webhooks_notificacion', [])
    
    if not webhooks:
        print("⚠️ No se encontraron webhooks en la sesión para notificación de finalización")
        return False

    # Construir el embed
    fields = []

    if apertura_code:
        fields.append({
            "name": "🔢 Código de apertura",
            "value": f"#{apertura_code}",
            "inline": False
        })

    fields.extend([
        {"name": "👤 Usuario", "value": usuario, "inline": False},
        {"name": "📁 Proyecto", "value": proyecto, "inline": False},
        {"name": "🏗️ Entorno", "value": entorno, "inline": False},
        {"name": "🕒 Fecha y hora de cierre", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "inline": False}
    ])

    if tiempo_resolucion:
        fields.append({
            "name": "⏱️ Duración total",
            "value": tiempo_resolucion,
            "inline": False
        })

    if folio and tipo_opcion:
        tipo_label = "Ticket" if tipo_opcion.lower() == "ticket" else "Tarea"
        fields.append({
            "name": f"🧾 {tipo_label}",
            "value": f"#{folio}",
            "inline": False
        })

    accesos_usados = []
    if acceso_bd:
        accesos_usados.append("Base de datos")
    if acceso_ftp:
        accesos_usados.append("FTP")

    if accesos_usados:
        fields.append({
            "name": "🔑 Accesos usados",
            "value": ", ".join(accesos_usados),
            "inline": False
        })

    embed = {
        "title": "✅ Solicitud de apertura finalizada",
        "color": 0x2ECC71,  # Verde
        "fields": fields,
        "footer": {
            "text": "Sistema Apleeks · Seguridad de red"
        }
    }

    payload = {
        "username": "Apleeks Bot",
        "embeds": [embed]
    }

    # Enviar a todos los webhooks guardados
    success = False
    for webhook_url in webhooks:
        try:
            response = requests.post(webhook_url, json=payload)
            if response.status_code == 204:
                success = True
                print(f"✅ Notificación de finalización enviada correctamente a {webhook_url}")
            else:
                print(f"❌ Falló el envío a Discord (webhook: {webhook_url}): {response.status_code} - {response.text}")
        except Exception as e:
            print(f"❌ Error al enviar notificación a Discord (webhook: {webhook_url}): {e}")

    return success




# ============================
#     EJECUCIÓN FLASK
# ============================

if __name__ == '__main__':
    app.run(debug=True)
