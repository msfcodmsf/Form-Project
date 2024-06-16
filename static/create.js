        function closeCreatePost() {
            window.location.href = 'index.html';
        }

        // Tüm dropdownları kapatan fonksiyon
function closeAllDropdowns() {
    const dropdowns = document.querySelectorAll('.dropdown-container');
    dropdowns.forEach(dropdown => {
        dropdown.style.display = 'none';
    });
}

// Sayfa üzerinde herhangi bir yere tıklandığında dropdown'ları kontrol eden event listener
document.addEventListener('click', function(event) {
    const isClickInsideDropdown = document.getElementById('resultsContainer').contains(event.target);
    if (!isClickInsideDropdown) {
        closeAllDropdowns();
    }
});

// Temizle butonunu hedefle
const clearButton = document.getElementById('clearButton');

// Temizle butonuna tıklanınca formu temizle
clearButton.addEventListener('click', function() {
    const form = document.querySelector('form');
    form.reset(); // Formu sıfırla
    const selectedLanguagesList = document.getElementById('selectedLanguagesList');
    selectedLanguagesList.innerHTML = ''; // Seçilen kategoriler listesini temizle
});

// Kategoriler penceresini açan fonksiyon
function openCategoriesDropdown() {
    document.getElementById('resultsContainer').style.display = 'block';
}

// Kategoriler penceresini kapatan fonksiyon
function closeCategoriesDropdown() {
    document.getElementById('resultsContainer').style.display = 'none';
}

// Sayfa üzerinde herhangi bir yere tıklandığında dropdown'ı kontrol eden event listener
document.addEventListener('click', function(event) {
    const dropdownButton = document.getElementById('searchBox');
    const dropdownContainer = document.getElementById('resultsContainer');

    // Dropdown'ın içine veya dropdown düğmesine tıklanmışsa, dropdown açık bırakılır
    if (event.target === dropdownButton || dropdownContainer.contains(event.target)) {
        openCategoriesDropdown();
    } else {
        // Dropdown'ın dışına tıklanmışsa, dropdown kapatılır
        closeCategoriesDropdown();
    }
});

// Dropdown açma fonksiyonları devam eder...



        // Dropdown ve arama fonksiyonları
        const searchBox = document.getElementById('searchBox');
        const resultsContainer = document.getElementById('resultsContainer');
        const selectedLanguagesList = document.getElementById('selectedLanguagesList');
        const categories = ['Category 1', 'Category 2', 'Category 3', 'Category 4', 'Category 5', 'Category 6', 'Category 7']; // Sample categories

        searchBox.addEventListener('focus', function() {
            displayInitialCategories();
        });

        searchBox.addEventListener('input', function() {
            const query = this.value.toLowerCase();
            resultsContainer.innerHTML = ''; // Clear previous results

            if (query.length > 0) {
                resultsContainer.style.display = 'block'; // Show the container if there's a query

                const filteredCategories = categories.filter(category => category.toLowerCase().includes(query));

                filteredCategories.forEach(category => {
                    const item = document.createElement('div');
                    item.className = 'dropdown-item';
                    item.textContent = category;
                    item.addEventListener('click', function() {
                        selectCategory(category);
                    });
                    resultsContainer.appendChild(item);
                });
            } else {
                displayInitialCategories();
            }
        });

        function displayInitialCategories() {
            resultsContainer.innerHTML = '';
            resultsContainer.style.display = 'block';

            const initialCategories = categories.slice(0, 5);

            initialCategories.forEach(category => {
                const item = document.createElement('div');
                item.className = 'dropdown-item';
                item.textContent = category;
                item.addEventListener('click', function() {
                    selectCategory(category);
                });
                resultsContainer.appendChild(item);
            });
        }

        // Create Post butonunu hedefle
const createPostButton = document.querySelector('.create-post-button');

// Create Post butonuna tıklandığında
createPostButton.addEventListener('click', function(event) {
    event.preventDefault(); // Formun otomatik olarak gönderilmesini engelle
    // Buraya Create Post işlevini ekleyebilirsin, örneğin:
    alert('Create Post butonuna tıklandı!');
});

// Toggle Theme butonunu hedefle
const themeToggleButton = document.getElementById('themeToggle');

// Toggle Theme butonuna tıklandığında
themeToggleButton.addEventListener('click', function() {
    const currentTheme = document.body.classList.contains('light-mode') ? 'night-mode' : 'light-mode';
    changeTheme(currentTheme);
});


        function selectCategory(category) {
            if (selectedLanguagesList.children.length < 3) {
                const selectedCategory = document.createElement('span');
                selectedCategory.className = 'dropdown-item';
                selectedCategory.textContent = category;
                selectedCategory.addEventListener('click', function() {
                    selectedLanguagesList.removeChild(selectedCategory);
                });
                selectedLanguagesList.appendChild(selectedCategory);
            } else {
                alert("En fazla 3 kategori seçebilirsiniz.");
            }
        }

        function changeTheme(theme) {
            document.body.classList.remove('light-mode', 'night-mode');
            document.body.classList.add(theme + '-mode');
            localStorage.setItem("tema", theme);
        }

                    // Tema ayarları
                    window.onload = function() {
            let tema = localStorage.getItem("tema") || "light";
            document.body.classList.add(tema + "-mode");
        };

        document.getElementById('themeToggle').addEventListener('click', function() {
            const currentTheme = document.body.classList.contains('light-mode') ? 'night-mode' : 'light-mode';
            changeTheme(currentTheme);
        });
