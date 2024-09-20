from src.model import RunContext
from src.util import Util
from datetime import datetime
from src.log import log
from prettytable import PrettyTable


class ReportRenderer:

    def __init__(self, run_context: RunContext) -> None:
        self.rc = run_context
        self.conf = run_context.config


    def print(self):
        self._report_main()

    def _report_main(self):
        log.color('')
        self._print_general_info_section()
        log.color('')
        self._print_object_level_section()
        log.color('')
        self._print_cert_version_stats_table()
        log.color('')
        self._print_secret_version_stats_table()


    def _print_general_info_section(self):
        log.color(f'{self._dbl_line(58)} Execution Report {self._dbl_line(58)}')
        log.color(f"{'started on:':<25} {self._friendly_time_str(Util.as_timezone(self.rc.started_on))}")
        log.color(f"{'ended on:':<25} {self._friendly_time_str(Util.as_timezone(self.rc.ended_on)):<25}")
        log.color('')

        log.color(f'{self._single_line(58)} Config {self._single_line(58)}')
        log.color(f"{'no_import_if_dest_exist:':<25} {str(self.conf.no_import_if_dest_exist)}")
        log.color(f"{'export_dir:':<25} {str(self.conf.export_dir)}")
        log.color(f"{'export_only:':<25} {str(self.conf.export_only)}")
        log.color(f"{'timezone:':<25} {str(self.conf.timezone)}")


    def _print_object_level_section(self):
        log.color(f'{self._single_line(58)} Object Level Summary {self._single_line(58)}')
        log.color(f"{'total certs:':<25} {str(self.rc.total_certs)}")
        log.color(f"{'exported certs:':<25} {str(self.rc.total_exported_certs)}/{str(self.rc.total_certs)}")
        log.color(f"{'imported certs:':<25} {str(self.rc.total_imported_certs)}/{str(self.rc.total_exported_certs)}")
        log.color('')
        log.color(f"{'total secrets:':<25} {str(self.rc.total_secrets)}")
        log.color(f"{'exported secrets:':<25} {str(self.rc.total_exported_secrets)}/{str(self.rc.total_secrets)}")
        log.color(f"{'imported secrets:':<25} {str(self.rc.total_imported_secrets)}/{str(self.rc.total_exported_secrets)}")


    def _print_cert_version_stats_table(self):
        log.color(f'{self._single_line(58)} Cert Version Level Summary {self._single_line(58)}')
        log.color('')

        # stats table
        stats_table = PrettyTable()
        stats_table.field_names = ["name", "total version", "exported version", "imported version"]
        
        for k, v in self.rc.cert_export_import_stats.items():
            total, exp, imp = v
            stats_table.add_row([k, total, exp, imp])


        # version detail table

        version_table = PrettyTable()
        version_table.field_names = ['name', 'version',  'type', 'expires on', 
                                          'exported', 'imported', 'enabled', 'expired', 
                                          'exportable', 'current', 'exist dest', 'deleted dest']
        
        for c in self.rc.src_vault.certs:
            for v in c.versions:
                version_table.add_row([c.name[:15], v.version[:5], v.type, Util.friendly_date_str(v.expires_on),
                                            '1' if v.is_exported else '-',
                                            '1' if v.is_imported else '-',
                                            '1' if v.enable else '-',
                                            '1' if v.is_expired else '-',
                                            '1' if v.is_cert_marked_as_exportable else '-',
                                            '1' if v.is_latest_version else '-',
                                            '1' if c.is_exists_in_dest_vault else '-',
                                            '1' if c.is_deleted_in_dest_vault else '-',
                                    ])

        log.color(stats_table) 
        log.color('')
        log.color(version_table)
                
    
    def _print_secret_version_stats_table(self):
        log.color(f'{self._single_line(58)} Secret Version Level Summary {self._single_line(58)}')
        log.color('')

        # stats table
        stats_table = PrettyTable()
        stats_table.field_names = ["name", "total version", "exported version", "imported version"]
        
        for k, v in self.rc.cert_export_import_stats.items():
            total, exp, imp = v
            stats_table.add_row([k, total, exp, imp])


        # version detail table

        version_table = PrettyTable()
        version_table.field_names = ['name', 'version',  'content type', 'expires on', 
                                    'exported', 'imported', 'enabled', 'expired', 
                                    'latest version', 'exist dest', 'deleted dest']
        
        for s in self.rc.src_vault.secrets:
            for v in s.versions:
                ct = v.content_type[:10] if v.content_type else ''
                version_table.add_row([s.name[:15], v.version[:5], ct, Util.friendly_date_str(v.expires_on),
                                            '1' if v.is_exported else '-',
                                            '1' if v.is_imported else '-',
                                            '1' if v.enabled else '-',
                                            '1' if v.is_expired else '-',
                                            '1' if v.is_latest_version else '-',
                                            '1' if s.is_exists_in_dest_vault else '-',
                                            '1' if s.is_deleted_in_dest_vault else '-',
                                    ])
                
        log.color(stats_table)
        log.color('')
        log.color(version_table)
            
        



    def _print_version_detail_matrix(self):
        pass

    def _single_line(self, length=10):
        dash = '-'
        for x in range(length):
            dash += '-'
        return dash
    
    def _dbl_line(self, length=10):
        dash = '='
        for x in range(length):
            dash += '='
        return dash
    
    def _friendly_time_str(self, d: datetime):
        return d.strftime('%Y %H:%M')