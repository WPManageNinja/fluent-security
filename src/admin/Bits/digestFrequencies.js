/**
 * How often the sign-in summary report can be sent, keyed the way
 * BasicTasksHandler::maybeSendDigestEMail() reads `digest_summary`.
 *
 * Shared by the settings screen and the setup wizard, so the two never offer a different
 * list for the same setting.
 *
 * @param $t the app's translate function
 * @return {Object}
 */
export default function digestFrequencies($t) {
    return {
        daily: $t('Daily'),
        sun: $t('Every Sunday'),
        mon: $t('Every Monday'),
        tue: $t('Every Tuesday'),
        wed: $t('Every Wednesday'),
        thu: $t('Every Thursday'),
        fri: $t('Every Friday'),
        sat: $t('Every Saturday'),
        monthly: $t('Monthly, on the 1st')
    };
}
