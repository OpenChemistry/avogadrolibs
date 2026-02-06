/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").

  CSVR Thermostat - Canonical Sampling through Velocity Rescaling
  Based on: Bussi, Donadio, Parrinello, J. Chem. Phys. 126, 014101 (2007)
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CSVRTHERMOSTAT_H
#define AVOGADRO_QTPLUGINS_CSVRTHERMOSTAT_H

#include <cmath>
#include <random>
#include <iostream>
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
  double target_temp; // Target temperature (K)
  double
    coupling_time; // Coupling time constant - MUST BE IN SAME UNITS AS dt (fs)
  double dt;       // Timestep (fs)
  unsigned int n_dof;      // Number of degrees of freedom
  bool auto_dof;           // Automatically calculate DOF from atom count
  bool remove_com;         // Remove COM motion during velocity initialization
  bool enable_diagnostics; // Enable diagnostic output

  std::mt19937 rng;
  std::normal_distribution<double> normal_dist;

  // Generate single Gaussian random number
  double gaussian_random() { return normal_dist(rng); }

  // Generate sum of squared Gaussian random numbers (chi-squared distribution)
  // For n degrees of freedom
  double sum_noises_squared(int n)
  {
    if (n <= 0)
      return 0.0;
    // didn't realize there was a chi-squared distribution
    std::chi_squared_distribution<double> chi2(n);
    return chi2(rng);
  }

public:
  CSVRThermostat(double T_target = 300.0, double timestep = 1.0,
                 double tau = 100.0, int ndof = 3, unsigned seed = 12345)
    : target_temp(T_target), coupling_time(tau), dt(timestep), n_dof(ndof),
      auto_dof(true), remove_com(true), enable_diagnostics(false), rng(seed),
      normal_dist(0.0, 1.0)
  {
    // IMPORTANT: Default coupling_time is now 100 fs (0.1 ps)
    // Previously was 10, which if interpreted as ps would be 10000 fs
    // Ensure coupling_time and dt are in the same units!
  }

  // Setters
  void setTargetTemperature(double T_target) { target_temp = T_target; }

  // IMPORTANT: tau must be in the same units as dt (femtoseconds)
  // Typical values: 100-1000 fs (0.1-1.0 ps)
  void setCouplingTime(double tau) { coupling_time = tau; }

  void setTimeStep(double timestep) { dt = timestep; }

  // Set number of degrees of freedom manually
  // For N atoms: 3N (periodic), 3N-3 (non-periodic, COM removed),
  //              3N-6 (non-periodic, COM and rotation removed)
  void setDegreesOfFreedom(int ndof)
  {
    n_dof = ndof;
    auto_dof = false; // Disable automatic calculation
  }

  // Enable/disable automatic DOF calculation (default: enabled)
  // When enabled, DOF = 3*N_atoms - 3 (assumes COM motion removed)
  void setAutoDOF(bool enable) { auto_dof = enable; }

  // Enable/disable COM removal during velocity initialization
  void setRemoveCOM(bool enable) { remove_com = enable; }

  // Enable/disable diagnostic output
  void setDiagnostics(bool enable) { enable_diagnostics = enable; }

  // Getters for diagnostics
  double getTargetTemperature() const { return target_temp; }
  double getCouplingTime() const { return coupling_time; }
  double getTimeStep() const { return dt; }
  int getDegreesOfFreedom() const { return n_dof; }

  // Calculate current kinetic energy in Joules (SI)
  // This returns the kinetic energy for the entire system, not per mole.
  double compute_kinetic_energy(const Eigen::VectorXd& velocities,
                                const Eigen::VectorXd& masses)
  {
    constexpr double Apfs_to_mps = 1e5;       // (m/s) / (Å/fs)
    constexpr double amu_to_kg = 1.66054e-27; // kg/amu

    double ke = 0.0;
    int n_atoms = masses.size() / 3;

    for (int i = 0; i < n_atoms; ++i) {
      Eigen::Vector3d v = velocities.segment<3>(3 * i);
      double v_mps_sq = v.squaredNorm() * Apfs_to_mps * Apfs_to_mps;
      double m_kg = masses[3 * i] * amu_to_kg;
      ke += 0.5 * m_kg * v_mps_sq;
    }
    return ke; // in Joules
  }

  // Calculate current temperature from kinetic energy
  double compute_temperature(const Eigen::VectorXd& velocities,
                             const Eigen::VectorXd& masses)
  {
    if (n_dof < 1)
      return 0.0;

    constexpr double kB_SI = 1.380649e-23; // J/K
    double ke = compute_kinetic_energy(velocities, masses);
    // T = 2 * KE / (n_dof * kB)
    return 2.0 * ke / (n_dof * kB_SI);
  }

  // Apply CSVR (Canonical Sampling through Velocity Rescaling) thermostat
  // Based on Bussi, Donadio, Parrinello, J. Chem. Phys. 126, 014101 (2007)
  //
  // This thermostat correctly samples the canonical ensemble by adding
  // stochastic terms to the velocity rescaling. Unlike Berendsen, it
  // produces correct fluctuations in kinetic energy.
  //
  // The algorithm implements Eq. (A7) from the paper:
  //   K_new = K_old * c + K_target * (1-c) * (sum_i R_i^2) / n_dof
  //         + 2 * sqrt(K_old * K_target * c * (1-c) / n_dof) * R_1
  //
  // where c = exp(-dt/tau), R_i are independent Gaussian random numbers,
  // and the sum is over n_dof terms.
  void apply(Eigen::VectorXd& velocities, const Eigen::VectorXd& masses)
  {
    constexpr double kB_SI = 1.380649e-23; // J/K

    // Update DOF if automatic mode is enabled
    if (auto_dof) {
      int n_atoms = masses.size() / 3;
      n_dof = 3 * n_atoms - 3; // Remove 3 DOF for COM translation
      if (n_dof < 1)
        n_dof = 1;
    }

    // Current kinetic energy in Joules
    double ke_current = compute_kinetic_energy(velocities, masses);

    if (ke_current < 1e-30) {
      if (enable_diagnostics) {
        std::cerr
          << "CSVR Warning: Near-zero kinetic energy, skipping thermostat\n";
      }
      return;
    }

    // Target kinetic energy from equipartition: KE = (n_dof/2) * kB * T
    double ke_target = 0.5 * n_dof * kB_SI * target_temp;

    // Exponential decay factor
    // CRITICAL: dt and coupling_time MUST be in the same units (both in fs)
    double c = std::exp(-dt / coupling_time);

    // Sanity check on c value
    if (c < 0.5 && enable_diagnostics) {
      std::cerr << "CSVR Warning: c=" << c << " is very small. "
                << "Check that dt (" << dt << ") and coupling_time ("
                << coupling_time << ") are in the same units (fs).\n";
    }

    // CSVR formula from Bussi et al. Eq. (A7)
    //
    // K_new = c * K + (1-c) * K_target / Nf * (R1² + sum_{i=2}^{Nf} Ri²)
    //       + 2 * sqrt(c * (1-c) * K * K_target / Nf) * R1
    //
    // where R1 is the SAME Gaussian in both the linear and quadratic terms.
    // This is a non-central chi-squared variate and is always non-negative.
    //
    // CRITICAL: The previous implementation replaced R1² with E[R1²] = 1
    // ("centering"), which broke the non-central chi-squared structure,
    // destroyed the R1/R1² correlation, and made ke_new occasionally negative.

    double R1 = gaussian_random();

    // Sum of (n_dof - 1) independent squared Gaussians (for i = 2..Nf)
    double sum_Rsq_rest = sum_noises_squared(n_dof - 1);

    // Full chi-squared sum includes R1² from the same draw
    double chi_sq_sum = R1 * R1 + sum_Rsq_rest;

    // Compute new kinetic energy using correct CSVR formula (Eq. A7)
    double ke_new =
      c * ke_current + (1.0 - c) * ke_target / n_dof * chi_sq_sum +
      2.0 * std::sqrt(c * (1.0 - c) * ke_current * ke_target / n_dof) * R1;

    // Safety net: The correct CSVR formula is a non-central chi-squared
    // variate and should always be non-negative. This guard should essentially
    // never fire, but we keep it for numerical safety (e.g., extreme
    // floating-point edge cases).
    if (ke_new < 0.0) {
      ke_new = ke_target * 0.01;
      if (enable_diagnostics) {
        std::cerr
          << "CSVR Warning: Negative KE computed (should be very rare "
             "with correct formula), clamping to small positive value\n";
      }
    }

    // Compute scaling factor
    double alpha = std::sqrt(ke_new / ke_current);

    // Rescale all velocities
    velocities *= alpha;

    // Diagnostic output
    if (enable_diagnostics) {
      double T_before = 2.0 * ke_current / (n_dof * kB_SI);
      double T_after = 2.0 * ke_new / (n_dof * kB_SI);
      std::cerr << "CSVR: T_before=" << T_before << " T_after=" << T_after
                << " T_target=" << target_temp << " alpha=" << alpha
                << " c=" << c << " n_dof=" << n_dof << "\n";
    }
  }

  // Initialize velocities to Maxwell-Boltzmann distribution at target
  // temperature velocities: 3N vector to be filled [vx0, vy0, vz0, vx1, vy1,
  // vz1, ...] masses: 3N vector [m0, m0, m0, m1, m1, m1, ...]
  void initializeVelocities(Eigen::VectorXd& velocities,
                            const Eigen::VectorXd& masses)
  {
    int n_atoms = masses.size() / 3;

    // Update DOF if automatic mode is enabled
    if (auto_dof) {
      n_dof = 3 * n_atoms - 3;
      if (n_dof < 1)
        n_dof = 1;
    }

    constexpr double kB_SI = 1.380649e-23;    // J/K
    constexpr double amu_to_kg = 1.66054e-27; // kg/amu
    constexpr double mps_to_Apfs = 1e-5;      // (Å/fs) / (m/s)

    // Generate Maxwell-Boltzmann distributed velocities
    for (int i = 0; i < n_atoms; ++i) {
      double mass_kg = masses[3 * i] * amu_to_kg;
      double sigma_mps = std::sqrt(kB_SI * target_temp / mass_kg);
      double sigma = sigma_mps * mps_to_Apfs;

      velocities[3 * i] = sigma * gaussian_random();
      velocities[3 * i + 1] = sigma * gaussian_random();
      velocities[3 * i + 2] = sigma * gaussian_random();
    }

    // Remove center of mass motion if enabled
    if (remove_com) {
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
    }

    // Rescale to exact target temperature
    double current_temp = compute_temperature(velocities, masses);
    if (current_temp > 0.0) {
      double scale = std::sqrt(target_temp / current_temp);
      velocities *= scale;
    }

    if (enable_diagnostics) {
      double final_temp = compute_temperature(velocities, masses);
      std::cerr << "CSVR: Initialized velocities at T=" << final_temp
                << "K (target=" << target_temp << "K)\n";
    }
  }

  // Reseed the random number generator
  void reseed(unsigned seed) { rng.seed(seed); }
};

} // namespace Avogadro::QtPlugins

#endif
