document.addEventListener('DOMContentLoaded', function () {
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');
    const body = document.body;

    const setTheme = (theme) => {
        if (theme === 'night') {
            body.classList.add('night-mode');
            themeIcon.classList.replace('fa-sun', 'fa-moon');
        } else if (theme === 'light') {
            body.classList.remove('night-mode');
            themeIcon.classList.replace('fa-moon', 'fa-sun');
        }
    };

    themeToggle.addEventListener('click', function () {
        let currentTheme = 'day';
        if (body.classList.contains('night-mode')) {
            currentTheme = 'night';
        } else if (body.style.getPropertyValue('--background-color') === 'rgb(255, 255, 255)') {
            currentTheme = 'light';
        }
        if (currentTheme === 'day') {
            setTheme('night');
            localStorage.setItem('theme', 'night');
        } else if (currentTheme === 'night') {
            setTheme('light');
            localStorage.setItem('theme', 'light');
        }
    });
    const savedTheme = localStorage.getItem('theme') || 'day';
    setTheme(savedTheme);
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



const languages = ["Python", "JavaScript", "Java", "C#", "C++", "PHP", "Ruby", "Swift", "Go", "Kotlin", "Rust"];
const searchBox = document.getElementById('searchBox');
const resultsContainer = document.getElementById('resultsContainer');
const selectedLanguages = [];
const selectedLanguagesSet = new Set();
const selectedLanguagesContainer = document.getElementById('selectedLanguagesContainer');
const selectedLanguagesList = document.getElementById('selectedLanguagesList');
const clearButton = document.getElementById('clearButton');

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



// Karakter Sayacı
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
