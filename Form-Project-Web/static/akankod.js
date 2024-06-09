const canvas = document.createElement('canvas');
document.body.appendChild(canvas);
document.body.style.margin = '0';
document.body.style.padding = '0';
document.body.style.overflow = 'auto';

const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

// Canvas arka plan rengini başlangıçta güncelle
updateCanvasBackgroundColor();

const hexa = [0, 1, '青', '红', '黄', '绿', '蓝', '紫', '黑', '白', '橙', '灰', '粉', '棕', '金', 'A', 'B', 'C', 'D', 'E', 'F', '银', '桃'];
let matrix = [];
let fontSize = 16;

// Matrisin boyutlarını güncelle
function updateMatrix() {
    matrix = [];
    for (let i = 0; i < canvas.width / fontSize; i++) {
        matrix[i] = 1;
    }
}
updateMatrix();

const draw = () => {
    ctx.fillStyle = getCurrentBackgroundColor();
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = 'rgb(0, 256, 0)';
    ctx.font = fontSize + "px monospace";

    for (let i = 0; i < matrix.length; i++) {
        let char = hexa[Math.floor(Math.random() * 15)];
        ctx.fillText(char, i * fontSize, matrix[i] * fontSize);

        matrix[i]++;
        if (matrix[i] * fontSize > canvas.height && Math.random() > 0.950) {
            matrix[i] = 0;
        }
    }
};

setInterval(draw, 30);

function getCurrentBackgroundColor() {
    return document.body.classList.contains('night-mode') ? 'rgb(28, 46, 69, 0.03)' : 'rgb(239, 242, 246, 0.03)';
}

function updateCanvasBackgroundColor() {
    canvas.style.backgroundColor = document.body.classList.contains('night-mode') ? '' : 'white';
}

// Tema değiştirme butonuna tıklama olayını dinle
document.getElementById('themeToggle').addEventListener('click', () => {
    document.body.classList.toggle('night-mode');
    document.body.classList.toggle('light-mode');
    updateCanvasBackgroundColor();

    // İkonu güncelle
    const themeIcon = document.getElementById('themeIcon');
    if (document.body.classList.contains('night-mode')) {
        themeIcon.classList.remove('fa-sun');
        themeIcon.classList.add('fa-moon');
    } else {
        themeIcon.classList.remove('fa-moon');
        themeIcon.classList.add('fa-sun');
    }
});

// Pencere yeniden boyutlandırıldığında canvas ve matrisi güncelle
window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    updateMatrix();
});
