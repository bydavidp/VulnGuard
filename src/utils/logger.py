"""
Configuración de logging para VulnGuard.
"""

import logging
import sys
from typing import Optional


# Formato detallado con timestamp, nivel y módulo
LOG_FORMAT = "[%(asctime)s] %(levelname)-8s %(name)-25s %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    verbose: bool = False,
) -> None:
    """
    Configura el sistema de logging.

    Args:
        level: Nivel de logging (default: INFO).
        log_file: Ruta opcional a un archivo de log.
        verbose: Si True, muestra logs más detallados (DEBUG).
    """
    if verbose:
        level = logging.DEBUG

    # Configurar handler de consola
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    console_handler.setFormatter(console_formatter)

    # Configurar logger raíz
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Limpiar handlers existentes
    root_logger.handlers.clear()

    root_logger.addHandler(console_handler)

    # Handler de archivo opcional
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

    # Silenciar logs de bibliotecas muy verbosas
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Obtiene un logger con el nombre del módulo.

    Args:
        name: Nombre del módulo (generalmente __name__).

    Returns:
        logging.Logger configurado.
    """
    return logging.getLogger(name)
