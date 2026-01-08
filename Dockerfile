# ===========================================
# iAnonymiser - Image Docker
# ===========================================

FROM python:3.12-slim

# Métadonnées
LABEL maintainer="folivanti"
LABEL description="Application d'anonymisation de logs et fichiers sensibles"
LABEL version="2.0"

# Variables d'environnement
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    PORT=5000

# Créer un utilisateur non-root pour la sécurité
RUN groupadd -r ianonymiser && useradd -r -g ianonymiser ianonymiser

# Répertoire de travail
WORKDIR /app

# Installer les dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copier les fichiers de dépendances d'abord (cache Docker)
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir gunicorn

# Copier le code source
COPY anonymizer.py .
COPY app.py .
COPY templates/ templates/

# Changer les permissions
RUN chown -R ianonymiser:ianonymiser /app

# Passer à l'utilisateur non-root
USER ianonymiser

# Port exposé
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Commande de démarrage avec Gunicorn (production-ready)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "120", "app:app"]

