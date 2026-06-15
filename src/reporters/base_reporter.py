"""
Clase base abstracta para los generadores de reportes.
"""

from abc import ABC, abstractmethod
from typing import Any

from src.core.models import AuditReport


class BaseReporter(ABC):
    """Clase base para reporters de salida."""

    def __init__(self, report: AuditReport):
        self.report = report

    @abstractmethod
    def generate(self, output_path: str = "") -> str:
        """
        Genera el reporte en el formato correspondiente.

        Args:
            output_path: Ruta de salida (opcional).

        Returns:
            str: Contenido generado o ruta del archivo.
        """
        ...
