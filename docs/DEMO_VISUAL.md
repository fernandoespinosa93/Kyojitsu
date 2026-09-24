# Interfaz y demo

La interfaz usa una paleta inspirada en el dashboard de Ikigai: fondo azul oscuro, paneles sobrios, azul para selección, violeta para generación LLM, verde para disponibilidad/defensa observada, ámbar para advertencia y coral para hallazgos o errores. Los estados incluyen texto: no dependen solo del color.

El menú de hamburguesa expande etiquetas y se pliega en escritorio y tablet. El panel principal tiene desplazamiento independiente. Las ayudas funcionan al pasar el cursor o enfocar con Tab. Se usan fuentes disponibles en el sistema, sin CDN ni archivos tipográficos incluidos.

`demo_visual.html` y `executive.pdf` de la raíz son una demostración SINTÉTICA. Las respuestas no proceden de la API del usuario. `run_demo.bat` vuelve a ejecutar ese laboratorio simulado. Para una prueba real abre Studio, elige API REST y comprueba la conexión.

El resumen ejecutivo prioriza hallazgos confirmados, pendientes, calidad de evidencia y recomendaciones. La matriz por marco conserva categorías no probadas o fuera de alcance. La vista Evidencia permite inspeccionar prompt, respuesta, clasificación y procedencia; Origen de variantes muestra relaciones entre rondas y una reproducción de casos grabados.
