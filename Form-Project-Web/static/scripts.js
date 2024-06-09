document.addEventListener('DOMContentLoaded', function () {
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');
    const matrixThemeToggle = document.getElementById('matrixThemeToggle'); // Yeni eklenen buton
    const body = document.body;

    const setTheme = (theme) => {
        if (theme === 'night') {
            body.classList.add('night-mode');
            themeIcon.classList.replace('fa-sun', 'fa-moon');
        } else if (theme === 'light') {
            body.classList.remove('night-mode');
            themeIcon.classList.replace('fa-moon', 'fa-sun');
        } else if (theme === 'lightmatrix') {
            body.classList.remove('night-mode');
            body.style.setProperty('--background-color', '#ffffff');
            body.style.setProperty('--text-color', '#00ff00');
            themeIcon.classList.remove('fa-moon', 'fa-sun');
            themeIcon.classList.add('fa-lightbulb');
            startMatrixTheme(); // Matrix temalarını başlat
        } else if (theme === 'nightmatrix') {
            body.classList.add('night-mode');
            body.style.setProperty('--background-color', '#000000');
            body.style.setProperty('--text-color', '#ff00ff');
            themeIcon.classList.remove('fa-moon', 'fa-sun');
            themeIcon.classList.add('fa-lightbulb');
            startMatrixTheme(); // Matrix temalarını başlat
        }
    };

    themeToggle.addEventListener('click', function () {
        let currentTheme = 'day';
        if (body.classList.contains('night-mode')) {
            currentTheme = 'night';
        } else if (body.style.getPropertyValue('--background-color') === 'rgb(255, 255, 255)') {
            currentTheme = 'light';
        } else if (body.style.getPropertyValue('--background-color') === 'rgb(0, 0, 0)') {
            currentTheme = 'nightmatrix';
        } else if (body.style.getPropertyValue('--background-color') === 'rgb(0, 255, 0)') {
            currentTheme = 'lightmatrix';
        }
        if (currentTheme === 'day') {
            setTheme('night');
            localStorage.setItem('theme', 'night');
        } else if (currentTheme === 'night') {
            setTheme('light');
            localStorage.setItem('theme', 'light');
        } else if (currentTheme === 'light') {
            setTheme('lightmatrix');
            localStorage.setItem('theme', 'lightmatrix');
        } else if (currentTheme === 'lightmatrix') {
            setTheme('nightmatrix');
            localStorage.setItem('theme', 'nightmatrix');
        } else if (currentTheme === 'nightmatrix') {
            setTheme('day');
            localStorage.setItem('theme', 'day');
        }
    });

    // Matrix temaları için buton dinleyicisi
    matrixThemeToggle.addEventListener('click', function () {
        setTheme('lightmatrix'); // Örnek olarak, lightmatrix temasını başlatıyorum
        localStorage.setItem('theme', 'lightmatrix');
    });

    const savedTheme = localStorage.getItem('theme') || 'day';
    setTheme(savedTheme);

    // Matrix temalarını başlatan fonksiyon
    function startMatrixTheme() {
        const canvas = document.createElement('canvas');
        document.body.appendChild(canvas);
        document.body.style.margin = '0';
        document.body.style.padding = '0';
        document.body.style.overflow = 'auto';

        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        updateCanvasBackgroundColor();

        const hexa = [0, 1, '青', '红', '黄', '绿', '蓝', '紫', '黑', '白', '橙', '灰', '粉', '棕', '金', 'A', 'B', 'C', 'D', 'E', 'F', '银', '桃'];
        let matrix = [];
        let fontSize = 16;

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

        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            updateMatrix();
        });
    }
});





function searchLanguages() {
    const input = document.getElementById('searchBox');
    const filter = input.value.toLowerCase();
    const nodes = document.getElementsByClassName('post');

    for (let i = 0; i < nodes.length; i++) {
        if (nodes[i].innerText.toLowerCase().includes(filter)) {
            nodes[i].style.display = "flex";
        } else {
            nodes[i].style.display = "none";
        }
    }
}

// ... (gece/gündüz modu kodları)

const languages = ["Python", "JavaScript", "Java", "C#", "C++", "PHP", "Ruby", "Swift", "Go", "Kotlin", "Rust"];
const searchBox = document.getElementById('searchBox');
const resultsContainer = document.getElementById('resultsContainer');
const selectedLanguages = [];
const selectedLanguagesSet = new Set();
const selectedLanguagesContainer = document.getElementById('selectedLanguagesContainer');
const selectedLanguagesList = document.getElementById('selectedLanguagesList');
const clearButton = document.getElementById('clearButton');

// Devam eden kodlarınız burada devam eder...

function searchLanguages() {
    const searchTerm = searchBox.value.toLowerCase();
    const filteredLanguages = languages.filter(lang => 
        lang.toLowerCase().includes(searchTerm) && !selectedLanguages.includes(lang) // Seçilmemiş dilleri filtrele
    );

    resultsContainer.innerHTML = '';
    filteredLanguages.forEach(lang => {
        const listItem = document.createElement('li');
        listItem.textContent = lang;
        listItem.onclick = () => selectLanguage(lang);
        resultsContainer.appendChild(listItem);
    });
}

function selectLanguage(language) {
    if (!selectedLanguagesSet.has(language)) {
        selectedLanguagesSet.add(language);
        updateSelectedLanguages();
    }
}

function updateSelectedLanguages() {
    resultsContainer.innerHTML = ''; // Önceki sonuçları temizle

    // Seçilen dilleri bir kez yazdır
    const selectedLanguagesHeader = document.createElement('div');
    selectedLanguagesHeader.textContent = "Seçilen Diller:";
    resultsContainer.appendChild(selectedLanguagesHeader);

    // Seçilen dillerin listesini oluştur
    const selectedLanguagesList = document.createElement('ul');
    selectedLanguagesSet.forEach(lang => {
        const listItem = document.createElement('li');
        listItem.textContent = lang;
        selectedLanguagesList.appendChild(listItem);
    });
    resultsContainer.appendChild(selectedLanguagesList);
}
updateSelectedLanguages();

clearButton.addEventListener('click', () => {
    selectedLanguagesSet.clear(); // Set'i temizle
    updateSelectedLanguages();
    searchBox.value = ''; // Arama kutusunu temizle
    searchLanguages(); // Arama sonuçlarını güncelle
});
  

(function(window, document, undefined){
    "use strict";
    var nightMode = document.cookie.indexOf("nightMode=true") !== -1;
    var lightMode = document.cookie.indexOf("nightMode=false") !== -1;
    if (nightMode){
      document.body.classList.add("night-mode");
    } else {
      document.body.classList.add("light-mode");
    }
    
    const userPrefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    const userPrefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;

    if (!lightMode && userPrefersDark){
        document.body.classList.add("night-mode");
    }
    if (!nightMode && userPrefersLight){
        document.body.classList.add("light-mode");
    }
})(window, document);

(function(window, document, undefined){
    "use strict";
    var nav = document.querySelector(".theme-mode");
    nav.innerHTML += '<span id="night-mode"><a role="button" title="nightMode" href="javascript:void(0);">🌓</a></span>';
    var nightMode = document.querySelector("#night-mode");
    nightMode.addEventListener("click", function(event){
        event.preventDefault();
        document.body.classList.toggle("light-mode");
        document.body.classList.toggle("night-mode");
        if (document.body.classList.contains("night-mode")){
            document.cookie = "nightMode=true; expires=Fri, 31 Dec 9999 23:59:59 GMT; path=/; secure;";
        } else {
            document.cookie = "nightMode=false; expires=Fri, 31 Dec 9999 23:59:59 GMT; path=/; secure;";
        }
    }, false);
})(window, document);

const canvas = document.createElement('canvas')
document.body.appendChild(canvas)
document.body.style.margin = '0'
document.body.style.padding = '0'
document.body.style.overflow = 'hidden'


const ctx = canvas.getContext('2d')
canvas.width = window.innerWidth
canvas.height = window.innerHeight

ctx.fillStyle = 'black'
ctx.fillRect(0,0, canvas.width, canvas.height)


const hexa = [1, 2, 3, 4, 5, 6, 7, 8, 9,
'A', 'B', 'C', 'D', 'E', 'F']
let matrix = []
let fontSize = 16


for(let i = 0; i<canvas.width/fontSize; i++){
    matrix[i] = 1
}


const draw=()=>{
    ctx.fillStyle = 'rgba(0, 0, 0, 0.03)'
    ctx.fillRect(0,0,canvas.width, canvas.height)

    ctx.fillStyle = 'rgb(0, 256, 0)'
    ctx.font = fontSize +"px monospace"

    for(let i = 0; i<matrix.length; i++){
        let char = hexa[Math.floor(Math.random()*15)]
        ctx.fillText(char, i*fontSize,
            matrix[i]*fontSize)

        matrix[i]++
        if(matrix[i]*fontSize>canvas.height && 
            Math.random()>0.950){
                matrix[i] = 0
            }

    }
}


setInterval(draw, 30)


document.addEventListener('DOMContentLoaded', function() {
  const baslik = document.getElementById("baslik");
  const etiketler = document.getElementById("etiketler");
  const gonderButton = document.getElementById("gonder");

  CKEDITOR.replace('editor'); // 'editor' div'ini CKEditor ile değiştirir

  gonderButton.addEventListener("click", () => {
    const editorData = CKEDITOR.instances.editor.getData(); // CKEditor içeriğini al
    // Burada editorData'yı (başlık, etiket, içerik) sunucuya gönderebilirsiniz.
    alert("Tartışma başlatıldı! İçerik:\n" + editorData);
  });
});

document.querySelectorAll('.text-block').forEach(block => {
    if (block.scrollWidth > block.clientWidth) {
        block.style.overflow = 'auto';
    }
});


var textarea = document.getElementById("content");
    var charCount = document.getElementById("charCount");

    textarea.addEventListener("input", function() {
        var charLength = textarea.value.length;
        charCount.textContent = "Characters: " + charLength + "/600";

        if (charLength > 600) {
            charCount.style.color = "red";
        } else {
            charCount.style.color = "black";
        }
    });
