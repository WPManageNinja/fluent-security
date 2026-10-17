const fs = require('node:fs');
const path = require('node:path');
const rtlcss = require('rtlcss');

const stylesheets = Object.freeze([
    ['dist/admin/element-plus.css', 'dist/admin/element-plus-rtl.css'],
    ['dist/admin/app.css', 'dist/admin/app-rtl.css'],
    ['dist/public/login_helper.css', 'dist/public/login_helper-rtl.css'],
    ['dist/public/login_customizer.css', 'dist/public/login_customizer-rtl.css']
]);

/**
 * Build the RTL counterpart for every stylesheet shipped by the plugin.
 *
 * The input files are compiled by Laravel Mix first. Running RTLCSS afterward means Sass,
 * Tailwind and Element Plus have already produced ordinary CSS, so every declaration that
 * reaches the browser passes through one direction-aware build step.
 *
 * @param {string} rootDir
 * @param {Array<Array<string>>} files
 * @returns {string[]}
 */
function generateRtlStylesheets(rootDir = path.resolve(__dirname, '..'), files = stylesheets) {
    return files.map(([sourcePath, outputPath]) => {
        const source = path.resolve(rootDir, sourcePath);
        const output = path.resolve(rootDir, outputPath);

        if (!fs.existsSync(source)) {
            throw new Error(`Cannot generate RTL stylesheet; missing ${sourcePath}`);
        }

        const css = fs.readFileSync(source, 'utf8');
        fs.writeFileSync(output, `${rtlcss.process(css)}\n`);

        return output;
    });
}

if (require.main === module) {
    for (const output of generateRtlStylesheets()) {
        console.log(`Generated ${path.relative(path.resolve(__dirname, '..'), output)}`);
    }
}

module.exports = {
    generateRtlStylesheets,
    stylesheets
};
