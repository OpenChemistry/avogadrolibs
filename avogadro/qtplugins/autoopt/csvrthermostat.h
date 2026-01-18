/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CSVRTHERMOSTAT_H
#define AVOGADRO_QTPLUGINS_CSVRTHERMOSTAT_H

#include <cmath>
#include <random>
#include <Eigen/Dense>

namespace Avogadro::QtPlugins {

// Unit conversion constants for MD with:
//   - positions in Angstroms (Å)
//   - time in femtoseconds (fs)
//   - mass in atomic mass units (amu)
//   - energy in kJ/mol (from force field)
//   - temperature in Kelvin (K)
//
// CRITICAL: The force field returns energy in kJ/mol, meaning the energy
// for one mole of the ENTIRE SYSTEM (not per atom). The gradient is thus
// in kJ/(mol·Å). For dynamics, we need accelerations that produce realistic
// atomic velocities.
//
// Physical constants:
//   kB = 1.380649e-23 J/K (Boltzmann constant)
//   NA = 6.02214076e23 /mol (Avogadro's number)
//   1 amu = 1.66054e-27 kg
//   1 Å = 1e-10 m
//   1 fs = 1e-15 s
//
namespace units {
// For temperature calculation from kinetic energy:
// T = 2 * KE / (n_dof * kB)
// where KE is in kJ/mol and we want T in K.
// Using R = kB * NA = 8.314 J/(mol·K) = 8.314e-3 kJ/(mol·K)
constexpr double kB = 8.314462618e-3; // kJ/(mol*K) - this is R

// Kinetic energy conversion:
// KE (kJ/mol) = 0.5 * sum_i(m_i * v_i²) * KINETIC_CONVERSION
// where m is in amu and v is in Å/fs.
//
// 1 amu·(Å/fs)² = 1.66054e-27 kg · (1e5 m/s)² = 1.66054e-17 J
// Per mole: 1.66054e-17 J · 6.022e23 = 10.0 kJ/mol
constexpr double KINETIC_CONVERSION = 10.0; // amu·(Å/fs)² to kJ/mol

// Force/acceleration conversion:
// The gradient from the force field is in kJ/(mol·Å).
// We want acceleration in Å/fs².
//
// From F = ma: a = F/m = [kJ/(mol·Å)] / [amu]
//
// 1 kJ/(mol·Å·amu) = 1000 J / (6.022e23 · 1e-10 m · 1.66054e-27 kg)
//                  = 1000 / (1e-13) m/s² = 1e16 m/s²
// In Å/fs²: 1e16 m/s² · 1e10 Å/m · (1e-15)² s²/fs² = 1e-4 Å/fs²
constexpr double FORCE_CONVERSION = 1e-4; // (kJ/mol/Å)/amu to Å/fs²
} // namespace units

class CSVRThermostat
{
private:
  double target_temp;   // Target temperature (K)
  double coupling_time; // Coupling time constant (ps or time units)
  double dt;            // Timestep
  int n_dof;            // Number of degrees of freedom
  std::mt19937 rng;
  std::normal_distribution<double> normal_dist;

  // Generate random kinetic energy from distribution
  double random_kinetic_energy(double mean_ke)
  {
    // For n degrees of freedom, kinetic energy follows chi-squared distribution
    // We need to generate sum of squares of n_dof Gaussian random numbers
    double sum = 0.0;
    for (int i = 0; i < n_dof; ++i) {
      double r = normal_dist(rng);
      sum += r * r;
    }
    return 0.5 * mean_ke * sum / n_dof;
  }

  // Generate single Gaussian random number
  double gaussian_random() { return normal_dist(rng); }

public:
  CSVRThermostat(double T_target = 300.0, double timestep = 1.0,
                 double tau = 10.0, int ndof = 3, unsigned seed = 12345)
    : target_temp(T_target), coupling_time(tau), dt(timestep), n_dof(ndof),
      rng(seed), normal_dist(0.0, 1.0)
  {
  }

  // set target temperature
  void setTargetTemperature(double T_target) { target_temp = T_target; }

  // set coupling time constant
  void setCouplingTime(double tau) { coupling_time = tau; }

  // set timestep
  void setTimeStep(double timestep) { dt = timestep; }

  // set number of degrees of freedom
  void setDegreesOfFreedom(int ndof) { n_dof = ndof; }

  // Calculate current kinetic energy in Joules (SI)
  // This returns the kinetic energy for the entire system, not per mole.
  double compute_kinetic_energy(const Eigen::VectorXd& velocities,
                                const Eigen::VectorXd& masses)
  {
    // Convert velocities from Å/fs to m/s, and masses from amu to kg
    constexpr double Apfs_to_mps = 1e5;       // (m/s) / (Å/fs)
    constexpr double amu_to_kg = 1.66054e-27; // kg/amu

    double ke = 0.0;
    int n_atoms = masses.size() / 3;

    // Velocities stored as [vx0, vy0, vz0, vx1, vy1, vz1, ...]
    // Masses stored as [m0, m0, m0, m1, m1, m1, ...]
    for (int i = 0; i < n_atoms; ++i) {
      Eigen::Vector3d v = velocities.segment<3>(3 * i);
      double v_mps_sq = v.squaredNorm() * Apfs_to_mps * Apfs_to_mps;
      double m_kg = masses[3 * i] * amu_to_kg;
      ke += 0.5 * m_kg * v_mps_sq;
    }
    return ke; // in Joules
  }

  // Apply CSVR (Canonical Sampling through Velocity Rescaling) thermostat
  // Based on Bussi, Donadio, Parrinello, J. Chem. Phys. 126, 014101 (2007)
  //
  // This thermostat correctly samples the canonical ensemble by adding
  // stochastic terms to the velocity rescaling. Unlike Berendsen, it
  // produces correct fluctuations in kinetic energy.
  void apply(Eigen::VectorXd& velocities, const Eigen::VectorXd& masses)
  {
    constexpr double kB_SI = 1.380649e-23; // J/K

    // Current kinetic energy in Joules
    double ke_current = compute_kinetic_energy(velocities, masses);

    if (ke_current < 1e-30)
      return; // Avoid division by zero

    // Target kinetic energy from equipartition: KE = (n_dof/2) * kB * T
    double ke_target = 0.5 * n_dof * kB_SI * target_temp;

    // CSVR scaling factor (Eq. A7 from Bussi et al.)
    // The new kinetic energy is:
    //   K_new = c*K + (1-c)*K_target + 2*sqrt(c*(1-c)*K*K_target/n_dof)*R1
    //           + (1-c)*K_target/n_dof * sum_{i=2}^{n_dof}(R_i^2)
    //
    // where c = exp(-dt/tau), and R_i are independent Gaussian random numbers.
    //
    // The scaling factor alpha = sqrt(K_new / K)

    double c = exp(-dt / coupling_time);

    // First Gaussian random number
    double R1 = gaussian_random();

    // Sum of (n_dof - 1) squared Gaussian random numbers
    // This approximates a chi-squared distribution with (n_dof-1) degrees of
    // freedom
    double sum_Rsq = 0.0;
    for (int i = 0; i < n_dof - 1; ++i) {
      double r = gaussian_random();
      sum_Rsq += r * r;
    }

    // Compute new kinetic energy using CSVR formula
    double ke_new =
      c * ke_current + (1.0 - c) * ke_target * sum_Rsq / n_dof +
      2.0 * sqrt(c * (1.0 - c) * ke_current * ke_target / n_dof) * R1;

    // Ensure ke_new is positive (can be negative due to stochastic term)
    if (ke_new < 0.0)
      ke_new = 0.0;

    // Compute scaling factor
    double alpha = sqrt(ke_new / ke_current);

    // Rescale all velocities
    velocities *= alpha;
  }

  // Calculate current temperature from kinetic energy
  double compute_temperature(const Eigen::VectorXd& velocities,
                             const Eigen::VectorXd& masses)
  {
    constexpr double kB_SI = 1.380649e-23;                  // J/K
    double ke = compute_kinetic_energy(velocities, masses); // in Joules
    // T = 2 * KE / (n_dof * kB)
    return 2.0 * ke / (n_dof * kB_SI);
  }

  // Initialize velocities to Maxwell-Boltzmann distribution at target
  // temperature velocities: 3N vector to be filled [vx0, vy0, vz0, vx1, vy1,
  // vz1, ...] masses: 3N vector [m0, m0, m0, m1, m1, m1, ...]
  void initializeVelocities(Eigen::VectorXd& velocities,
                            const Eigen::VectorXd& masses)
  {
    int n_atoms = masses.size() / 3;

    // Use SI-based calculation for physically correct velocities.
    // For each velocity component: sigma = sqrt(kB_SI * T / m_SI)
    //
    // kB_SI = 1.380649e-23 J/K
    // m_SI = mass_amu * 1.66054e-27 kg
    // Result is in m/s, convert to Å/fs by multiplying by 1e-5
    //
    // For H at 300K: sigma = sqrt(1.38e-23 * 300 / 1.66e-27) * 1e-5
    //                      = sqrt(2.49e6) * 1e-5 = 1579 * 1e-5 = 0.016 Å/fs
    //
    constexpr double kB_SI = 1.380649e-23;    // J/K
    constexpr double amu_to_kg = 1.66054e-27; // kg/amu
    constexpr double mps_to_Apfs = 1e-5;      // (Å/fs) / (m/s)

    for (int i = 0; i < n_atoms; ++i) {
      double mass_kg = masses[3 * i] * amu_to_kg;
      double sigma_mps = sqrt(kB_SI * target_temp / mass_kg);
      double sigma = sigma_mps * mps_to_Apfs;

      velocities[3 * i] = sigma * gaussian_random();
      velocities[3 * i + 1] = sigma * gaussian_random();
      velocities[3 * i + 2] = sigma * gaussian_random();
    }

    // Remove center of mass motion
    Eigen::Vector3d total_momentum = Eigen::Vector3d::Zero();
    double total_mass = 0.0;
    for (int i = 0; i < n_atoms; ++i) {
      double mass = masses[3 * i];
      total_momentum += mass * velocities.segment<3>(3 * i);
      total_mass += mass;
    }
    Eigen::Vector3d com_velocity = total_momentum / total_mass;

    for (int i = 0; i < n_atoms; ++i) {
      velocities.segment<3>(3 * i) -= com_velocity;
    }

    // Rescale to exact target temperature
    double current_temp = compute_temperature(velocities, masses);
    if (current_temp > 0.0) {
      double scale = sqrt(target_temp / current_temp);
      velocities *= scale;
    }
  }
};

} // namespace Avogadro::QtPlugins

#endif
