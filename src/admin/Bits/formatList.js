/**
 * Joins a list the way the admin's language does: "A, B and C" or "A, B or C".
 *
 * The browser already knows each language's commas and its word for "and" / "or",
 * so a translated "or" is never glued between fragments, which cannot be translated.
 *
 * @param {Array} values
 * @param {String} type 'conjunction' (and) or 'disjunction' (or)
 * @return {String}
 */
export default function formatList(values, type = 'conjunction') {
    try {
        return new Intl.ListFormat(document.documentElement.lang || 'en', {type}).format(values);
    } catch (e) {
        return values.join(', ');
    }
}
