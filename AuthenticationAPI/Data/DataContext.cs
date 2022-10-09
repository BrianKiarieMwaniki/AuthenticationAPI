

namespace AuthenticationAPI.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {

        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            optionsBuilder.UseSqlServer("Server=BRIAN\\SQLEXPRESS;Database=userdb;Trusted_Connection=true;");
        }

        public DbSet<User> Users => Set<User>();
    }
}
